mod support;

use automata_ci_core::{LogicalJobKind, TransportProtocol, WorkflowEventProvenance};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, DiagnosticKind, GithubWorkflowCompiler, GithubWorkflowSourcePlan, Job,
    JobContainer, JobServices, ScalarResolution,
};

const MALFORMED_CONTAINER_DIAGNOSTICS: [(&str, &str); 14] = [
    (
        "github.expected_job_container",
        "jobs.bad-container.container",
    ),
    ("github.expected_job_services", "jobs.bad-services.services"),
    (
        "github.expected_service_container",
        "jobs.bad-service.services.cache",
    ),
    (
        "github.expected_container_image",
        "jobs.bad-fields.container.image",
    ),
    (
        "github.expected_container_credentials",
        "jobs.bad-fields.container.credentials",
    ),
    (
        "github.expected_container_environment",
        "jobs.bad-fields.container.env",
    ),
    (
        "github.expected_container_ports",
        "jobs.bad-fields.container.ports",
    ),
    (
        "github.expected_container_volumes",
        "jobs.bad-fields.container.volumes[0]",
    ),
    (
        "github.expected_container_options",
        "jobs.bad-fields.container.options",
    ),
    ("github.expected_service_id", "jobs.bad-fields.services"),
    (
        "github.expected_container_credential",
        "jobs.bad-fields.services.api.credentials.username",
    ),
    (
        "github.expected_container_environment_name",
        "jobs.bad-fields.services.api.env",
    ),
    (
        "github.expected_container_environment_value",
        "jobs.bad-fields.services.api.env.CONFIG",
    ),
    (
        "github.expected_container_ports",
        "jobs.bad-fields.services.api.ports[0]",
    ),
];

const UNSUPPORTED_SERVICE_CASES: [(&str, &str); 4] = [
    (
        r"on: workflow_dispatch
jobs:
  test:
    runs-on: linux
    services:
      database:
        image: registry.example/database@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
        credentials: {username: user, password: pass}
    steps: [{run: echo test}]
",
        "github.compile.service_credentials",
    ),
    (
        r"on: workflow_dispatch
jobs:
  test:
    runs-on: linux
    services:
      database:
        image: registry.example/database@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
        volumes: [data:/var/lib/data]
    steps: [{run: echo test}]
",
        "github.compile.service_volumes",
    ),
    (
        r"on: workflow_dispatch
jobs:
  test:
    runs-on: linux
    services:
      database:
        image: registry.example/database@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
        options: --privileged
    steps: [{run: echo test}]
",
        "github.compile.service_options",
    ),
    (
        r"on: workflow_dispatch
jobs:
  test:
    runs-on: linux
    services:
      database:
        image: registry.example/database@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
        ports: [70000:5432]
    steps: [{run: echo test}]
",
        "github.compile.invalid_service_port",
    ),
];

#[test]
fn source_model_retains_job_and_service_container_forms() {
    let source = r#"on: push
jobs:
  verify:
    runs-on: linux
    container:
      image: registry.example.invalid/build:${{ matrix.version }}
      credentials:
        username: ${{ github.actor }}
        password: ${{ secrets.CONTAINER_TOKEN }}
      env:
        MODE: validation
        RETRIES: 3
      ports:
        - 8080
        - "8443:443"
        - ${{ inputs.debug_port }}
      volumes:
        - cache:/workspace/cache
        - ${{ inputs.workspace_mount }}
      options: --cpus 2
    services:
      cache: redis:7
      database:
        image: registry.example.invalid/database:16
        credentials:
          username: service-user
          password: ${{ secrets.DATABASE_TOKEN }}
        env:
          DATABASE_NAME: validation
        ports: [5432, "15432:5432"]
        volumes: [database:/var/lib/database]
        options: --health-cmd ready
    steps:
      - run: echo verify
"#;

    let report = support::parse(source);
    assert!(
        report.is_accepted(),
        "source diagnostics: {:#?}",
        report.diagnostics()
    );
    let plan = report.plan().expect("source plan");
    let job = plan.workflow().jobs()[0].job();

    assert_detailed_job_container(plan, job);
    assert_services(plan, job.services().expect("services"));
}

fn assert_detailed_job_container(plan: &GithubWorkflowSourcePlan, job: &Job) {
    let JobContainer::Detailed(container) = job.container().expect("job container") else {
        panic!("mapping container must remain detailed");
    };
    assert_eq!(
        container.image().expect("image").decoded(),
        "registry.example.invalid/build:${{ matrix.version }}"
    );
    assert!(
        container
            .image()
            .expect("image")
            .contains_expression_candidate()
    );
    let credentials = container.credentials().expect("credentials");
    assert_eq!(
        credentials.username().expect("username").decoded(),
        "${{ github.actor }}"
    );
    assert_eq!(
        credentials.password().expect("password").decoded(),
        "${{ secrets.CONTAINER_TOKEN }}"
    );
    assert!(credentials.extensions().is_empty());

    let environment = container.environment().expect("container environment");
    assert_eq!(environment.values().entries().len(), 2);
    assert_eq!(environment.values().entries()[0].key().value(), "MODE");
    assert_eq!(
        environment.values().entries()[1].value().resolution(),
        ScalarResolution::Integer
    );
    let ports = container.ports().expect("ports");
    assert_eq!(ports.values().len(), 3);
    assert_eq!(ports.values()[0].resolution(), ScalarResolution::Integer);
    assert_eq!(ports.values()[1].decoded(), "8443:443");
    assert!(ports.values()[2].contains_expression_candidate());
    let volumes = container.volumes().expect("volumes");
    assert_eq!(volumes.values()[0].decoded(), "cache:/workspace/cache");
    assert!(volumes.values()[1].contains_expression_candidate());
    assert_eq!(container.options().expect("options").decoded(), "--cpus 2");
    assert!(container.extensions().is_empty());
    assert!(
        plan.source()
            .slice(container.span())
            .expect("container source")
            .contains("credentials:")
    );
}

fn assert_services(plan: &GithubWorkflowSourcePlan, services: &JobServices) {
    assert_eq!(services.len(), 2);
    assert!(!services.is_empty());
    assert_eq!(services.entries()[0].id().value(), "cache");
    let JobContainer::Image(cache) = services.entries()[0].container() else {
        panic!("scalar service must remain an image shorthand");
    };
    assert_eq!(cache.decoded(), "redis:7");
    assert_eq!(
        plan.source()
            .slice(services.entries()[0].span())
            .expect("service entry source")
            .trim(),
        "cache: redis:7"
    );

    let JobContainer::Detailed(database) = services.entries()[1].container() else {
        panic!("mapping service must remain detailed");
    };
    assert_eq!(
        database.image().expect("service image").decoded(),
        "registry.example.invalid/database:16"
    );
    assert_eq!(database.ports().expect("service ports").values().len(), 2);
    assert_eq!(
        database.volumes().expect("service volumes").values()[0].decoded(),
        "database:/var/lib/database"
    );
    assert_eq!(
        database.options().expect("service options").decoded(),
        "--health-cmd ready"
    );
}

#[test]
fn empty_scalar_images_are_retained_for_conditional_disable_semantics() {
    let source = r#"on: push
jobs:
  verify:
    runs-on: linux
    container: ""
    services:
      cache: ""
      disabled: null
      conditional:
        image: ${{ inputs.enabled && 'cache:latest' || '' }}
    steps:
      - run: echo verify
"#;

    let report = support::parse(source);
    assert!(
        report.is_accepted(),
        "source diagnostics: {:#?}",
        report.diagnostics()
    );
    let job = report.plan().expect("source plan").workflow().jobs()[0].job();
    assert!(matches!(
        job.container(),
        Some(JobContainer::Image(image)) if image.decoded().is_empty()
    ));
    let services = job.services().expect("services");
    assert!(matches!(
        services.entries()[0].container(),
        JobContainer::Image(image) if image.decoded().is_empty()
    ));
    assert!(
        matches!(
            services.entries()[1].container(),
            JobContainer::Image(image) if image.resolution() == ScalarResolution::Null
        ),
        "YAML null remains typed for later GitHub string coercion"
    );
    assert!(
        services.entries()[2]
            .container()
            .image()
            .expect("conditional image")
            .contains_expression_candidate()
    );
}

#[test]
fn container_extensions_are_preserved_at_exact_paths() {
    let source = r"on: push
jobs:
  verify:
    runs-on: linux
    container:
      image: build:latest
      credentials:
        username: user
        password: token
        helper: external
      pull-policy: always
    services:
      cache:
        image: cache:latest
        restart-policy: on-failure
    steps:
      - run: echo verify
";

    let report = support::parse(source);
    assert!(!report.is_accepted());
    let plan = report.plan().expect("loss-aware source plan");
    let job = plan.workflow().jobs()[0].job();
    let container = job
        .container()
        .and_then(JobContainer::detailed)
        .expect("detailed job container");
    assert_eq!(
        container.credentials().expect("credentials").extensions()[0].path(),
        "jobs.verify.container.credentials.helper"
    );
    assert_eq!(
        container.extensions()[0].path(),
        "jobs.verify.container.pull-policy"
    );
    let service = job.services().expect("services").entries()[0]
        .container()
        .detailed()
        .expect("detailed service");
    assert_eq!(
        service.extensions()[0].path(),
        "jobs.verify.services.cache.restart-policy"
    );
    for path in [
        "jobs.verify.container.credentials.helper",
        "jobs.verify.container.pull-policy",
        "jobs.verify.services.cache.restart-policy",
    ] {
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic.kind() == DiagnosticKind::Unsupported
                && diagnostic.code() == "github.unsupported_field"
                && diagnostic.message().contains(path)
        }));
    }
}

#[test]
fn malformed_container_shapes_have_field_specific_diagnostics() {
    let source = r#"on: push
jobs:
  bad-container:
    runs-on: linux
    container: [build]
    steps: [{run: echo verify}]
  bad-services:
    runs-on: linux
    services: [cache]
    steps: [{run: echo verify}]
  bad-service:
    runs-on: linux
    services:
      cache: [image]
    steps: [{run: echo verify}]
  bad-fields:
    runs-on: linux
    container:
      image: [build]
      credentials: token
      env: [MODE=validation]
      ports: 8080
      volumes:
        - ""
        - null
        - {source: cache}
      options: [--cpus, 1]
    services:
      "": cache:latest
      api:
        image: api:latest
        credentials:
          username: ""
          password: [token]
        env:
          "": value
          CONFIG: [value]
        ports: [""]
    steps: [{run: echo verify}]
"#;

    let report = support::parse(source);
    assert!(report.plan().is_some(), "loss-aware source plan");
    for (code, path) in MALFORMED_CONTAINER_DIAGNOSTICS {
        assert!(
            report.diagnostics().iter().any(|diagnostic| {
                diagnostic.kind() == DiagnosticKind::Semantic
                    && diagnostic.code() == code
                    && diagnostic.message().contains(path)
            }),
            "missing {code} for {path}: {:#?}",
            report.diagnostics()
        );
    }
}

#[test]
fn reusable_workflow_calls_reject_step_job_container_fields() {
    let source = r"on: push
jobs:
  delegated:
    uses: ./.github/workflows/delegated.yml
    container: build:latest
    services:
      cache: cache:latest
";

    let report = support::parse(source);
    let conflicts = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == "github.step_job_field_on_reusable_workflow_call")
        .collect::<Vec<_>>();
    assert_eq!(conflicts.len(), 2);
    assert!(conflicts.iter().all(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Semantic
            && (diagnostic.message().contains("delegated.container")
                || diagnostic.message().contains("delegated.services"))
    }));
    let job = report.plan().expect("loss-aware plan").workflow().jobs()[0].job();
    assert!(job.container().is_some());
    assert!(job.services().is_some());
}

#[test]
fn current_lowering_rejects_job_containers_and_mutable_service_images() {
    let source = r"on: workflow_dispatch
jobs:
  verify:
    runs-on: linux
    container: build:latest
    services:
      cache:
        image: cache:latest
    steps:
      - run: echo verify
";

    let parsed = support::parse(source);
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    let source_plan = parsed.plan().expect("source plan");
    let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        source_plan,
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
    ));
    assert!(report.plan().is_none());
    let container = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.compile.job_container")
        .expect("container lowering diagnostic");
    assert_eq!(container.kind(), DiagnosticKind::Unsupported);
    assert_eq!(
        source_plan.source().slice(container.primary_span()),
        Some("build:latest")
    );

    let services = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.compile.mutable_service_image")
        .expect("services lowering diagnostic");
    assert_eq!(services.kind(), DiagnosticKind::Unsupported);
    assert_eq!(
        source_plan.source().slice(services.primary_span()),
        Some("cache:latest")
    );
}

#[test]
fn current_lowering_retains_supported_service_execution_templates() {
    let source = r#"on: workflow_dispatch
jobs:
  verify:
    runs-on: linux
    services:
      database:
        image: registry.example/database@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
        env:
          DATABASE_NAME: synthetic
          DATABASE_TOKEN: ${{ secrets.SYNTHETIC_TOKEN }}
        ports: [5432:5432, 5353/udp]
        options: --health-cmd "ready --database synthetic" --health-interval 5s
    steps:
      - run: echo verify
"#;

    let parsed = support::parse(source);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
    ));
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let LogicalJobKind::Steps(job) = report.plan().expect("plan").jobs()[0].execution() else {
        panic!("step job");
    };
    let [service] = job.services() else {
        panic!("one service");
    };
    assert_eq!(service.key().value().as_str(), "database");
    assert_eq!(service.environment().entries().len(), 2);
    assert_eq!(service.ports()[0].value().container_port(), 5432);
    assert_eq!(service.ports()[0].value().requested_host_port(), Some(5432));
    assert_eq!(
        service.ports()[0].value().protocol(),
        TransportProtocol::Tcp
    );
    assert_eq!(service.ports()[1].value().container_port(), 5353);
    assert_eq!(service.ports()[1].value().requested_host_port(), None);
    assert_eq!(
        service.ports()[1].value().protocol(),
        TransportProtocol::Udp
    );
    assert_eq!(service.options()[1].value(), "ready --database synthetic");
}

#[test]
fn current_lowering_rejects_unimplemented_or_invalid_service_surface() {
    for (source, code) in UNSUPPORTED_SERVICE_CASES {
        let parsed = support::parse(source);
        assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
        let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
            parsed.plan().expect("source plan"),
            WorkflowEventProvenance::new("github", "workflow_dispatch"),
        ));
        assert!(report.plan().is_none(), "unexpected plan for `{code}`");
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == code),
            "missing `{code}`: {:#?}",
            report.diagnostics()
        );
    }
}
