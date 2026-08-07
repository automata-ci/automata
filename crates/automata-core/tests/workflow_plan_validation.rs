use automata_core::{
    DeferredBoolean, ExpressionSegment, Located, PlanSourceLocation, PlanSourceOrigin,
    PlanSourceSpan, PlanValue, PlannedJob, PlannedStep, PlannedStepKind, RunStepPlan,
    RunnerProfile, WorkflowEventProvenance, WorkflowJobKey, WorkflowPermissions, WorkflowPlan,
    WorkflowPlanError, WorkflowSourceProvenance, WorkflowStepKey,
};

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "workflow.yml",
        PlanSourceLocation::new(0, 1, 1).expect("location"),
        PlanSourceLocation::new(1, 1, 2).expect("location"),
    )
    .expect("span")
}

fn job(key: &str, needs: &[&str]) -> PlannedJob {
    let step = PlannedStep::builder(
        WorkflowStepKey::new("position/00000000").expect("step key"),
        PlannedStepKind::Run(Box::new(RunStepPlan::new(
            Located::new(PlanValue::Literal("echo ok".to_owned()), span()),
            None,
            None,
        ))),
        span(),
    )
    .build()
    .expect("step");
    PlannedJob::builder(
        Located::new(WorkflowJobKey::new(key).expect("job key"), span()),
        RunnerProfile::new(
            None,
            vec![Located::new(PlanValue::Literal("linux".to_owned()), span())],
            span(),
        ),
        vec![step],
        span(),
    )
    .needs(
        needs
            .iter()
            .map(|dependency| {
                Located::new(
                    WorkflowJobKey::new(*dependency).expect("dependency key"),
                    span(),
                )
            })
            .collect(),
    )
    .timeout_seconds(Some(600))
    .build()
    .expect("job-local semantics")
}

fn plan(jobs: Vec<PlannedJob>) -> Result<WorkflowPlan, WorkflowPlanError> {
    WorkflowPlan::builder(
        WorkflowSourceProvenance::new(
            "github",
            "workflow.yml",
            PlanSourceOrigin::Memory {
                name: "workflow.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "push"),
        jobs,
        span(),
    )
    .build()
}

#[test]
fn valid_plan_round_trips_and_deserialization_revalidates_it() {
    let plan = plan(vec![job("build", &[])]).expect("valid plan");
    let encoded = serde_json::to_value(&plan).expect("serialize");
    let decoded: WorkflowPlan = serde_json::from_value(encoded.clone()).expect("deserialize");
    assert_eq!(decoded, plan);

    let mut unsupported_version = encoded.clone();
    unsupported_version["version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<WorkflowPlan>(unsupported_version).is_err());

    let mut zero_line = encoded;
    zero_line["span"]["start"]["line"] = serde_json::json!(0);
    assert!(serde_json::from_value::<WorkflowPlan>(zero_line).is_err());
}

#[test]
fn standalone_job_and_step_deserialization_revalidate_invariants() {
    let valid_job = job("build", &[]);
    let valid_step = valid_job.steps()[0].clone();

    let encoded_step = serde_json::to_value(&valid_step).expect("serialize step");
    let decoded_step: PlannedStep =
        serde_json::from_value(encoded_step.clone()).expect("deserialize valid step");
    assert_eq!(decoded_step, valid_step);

    let mut zero_step_timeout = encoded_step.clone();
    zero_step_timeout["timeout_seconds"] = serde_json::json!(0);
    assert!(serde_json::from_value::<PlannedStep>(zero_step_timeout).is_err());

    let mut unknown_step_field = encoded_step;
    unknown_step_field["future_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PlannedStep>(unknown_step_field).is_err());

    let encoded_job = serde_json::to_value(&valid_job).expect("serialize job");
    let decoded_job: PlannedJob =
        serde_json::from_value(encoded_job.clone()).expect("deserialize valid job");
    assert_eq!(decoded_job, valid_job);

    let mut no_steps = encoded_job.clone();
    no_steps["steps"] = serde_json::json!([]);
    assert!(serde_json::from_value::<PlannedJob>(no_steps).is_err());

    let mut unknown_job_field = encoded_job;
    unknown_job_field["future_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PlannedJob>(unknown_job_field).is_err());
}

#[test]
fn durable_v1_schema_rejects_unknown_fields_at_nested_boundaries() {
    let encoded = serde_json::to_value(plan(vec![job("build", &[])]).expect("valid plan"))
        .expect("serialize plan");

    for object_pointer in [
        "",
        "/source",
        "/source/origin",
        "/event",
        "/span",
        "/span/start",
        "/environment",
        "/run_defaults",
        "/jobs/0",
        "/jobs/0/key",
        "/jobs/0/runner",
        "/jobs/0/runner/labels/0/value",
        "/jobs/0/steps/0",
        "/jobs/0/steps/0/execution",
        "/jobs/0/steps/0/execution/value",
        "/jobs/0/steps/0/execution/value/script/value",
    ] {
        let mut adversarial = encoded.clone();
        adversarial
            .pointer_mut(object_pointer)
            .and_then(serde_json::Value::as_object_mut)
            .expect("test pointer must select an object")
            .insert("future_field".to_owned(), serde_json::json!(true));

        assert!(
            serde_json::from_value::<WorkflowPlan>(adversarial).is_err(),
            "unknown field at `{object_pointer}` was silently discarded"
        );
    }
}

#[test]
fn tagged_v1_values_reject_unknown_envelope_fields() {
    fn with_unknown_field<T: serde::Serialize>(value: &T) -> serde_json::Value {
        let mut encoded = serde_json::to_value(value).expect("serialize tagged value");
        encoded
            .as_object_mut()
            .expect("tagged value must be an object")
            .insert("future_field".to_owned(), serde_json::json!(true));
        encoded
    }

    assert!(
        serde_json::from_value::<ExpressionSegment>(with_unknown_field(
            &ExpressionSegment::Literal("text".to_owned())
        ))
        .is_err()
    );
    assert!(
        serde_json::from_value::<PlanValue>(with_unknown_field(&PlanValue::Literal(
            "text".to_owned()
        )))
        .is_err()
    );
    assert!(
        serde_json::from_value::<DeferredBoolean>(with_unknown_field(&DeferredBoolean::Literal(
            true
        )))
        .is_err()
    );
    assert!(
        serde_json::from_value::<WorkflowPermissions>(with_unknown_field(
            &WorkflowPermissions::ReadAll(span())
        ))
        .is_err()
    );
    assert!(
        serde_json::from_value::<PlannedStepKind>(with_unknown_field(
            job("build", &[]).steps()[0].execution()
        ))
        .is_err()
    );
}

#[test]
fn dependency_edges_must_exist_and_the_graph_must_be_acyclic() {
    assert!(matches!(
        plan(vec![job("build", &["missing"])]),
        Err(WorkflowPlanError::UnknownDependency { .. })
    ));
    assert_eq!(
        plan(vec![job("first", &["second"]), job("second", &["first"])]),
        Err(WorkflowPlanError::DependencyCycle)
    );
    assert_eq!(
        plan(vec![job("build", &["build"])]),
        Err(WorkflowPlanError::SelfDependency("build".to_owned()))
    );
}
