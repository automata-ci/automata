use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use automata_ci_ui_renderer::{
    MAX_RENDER_REQUEST_UTF8_BYTES, RenderError, RenderPolicy, Renderer, ResourceLimit,
    WasmtimeRenderer, client_assets,
};
use serde_json::{Value, json};

fn valid_request() -> Value {
    let assets = client_assets();
    json!({
        "schemaVersion": 1,
        "host": {
            "locale": "en",
            "cspNonce": "renderer-test-nonce",
            "assets": {
                "clientEntry": assets.script_path,
                "stylesheets": assets.stylesheet_paths,
            }
        },
        "page": {
            "kind": "run-list",
            "shell": {
                "productName": "Automata",
                "homeHref": "/repositories",
                "signIn": {
                    "action": "/auth/github/login",
                    "returnPath": "/automata-ci/automata/actions?status=in_progress"
                },
                "signOut": null,
                "documentTitle": "Workflow runs",
                "description": "Workflow runs for Automata",
                "viewer": null,
                "navigation": [
                    { "label": "Repositories", "href": "/repositories", "current": false },
                    { "label": "Actions", "href": "/automata-ci/automata/actions", "current": true }
                ]
            },
            "repository": {
                "owner": "automata-ci",
                "name": "automata",
                "sourceHref": "https://github.com/automata-ci/automata",
                "runsHref": "/automata-ci/automata/actions",
                "settingsHref": null
            },
            "heading": "Workflow runs",
            "summary": "<script>globalThis.compromised=true</script>",
            "filters": {
                "action": "/automata-ci/automata/actions",
                "status": "all",
                "branch": "main",
                "clearHref": "/automata-ci/automata/actions"
            },
            "workflowNavigation": null,
            "runs": [{
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "number": "1842",
                "name": "Build and test",
                "workflowName": "CI",
                "workflowHref": "/automata-ci/automata/actions/workflows/11111111-1111-4111-8111-11111111111a",
                "href": "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000",
                "status": { "label": "In progress", "tone": "running" },
                "sourceRef": {
                    "name": "main",
                    "kind": "branch",
                    "href": "https://github.com/automata-ci/automata/tree/main"
                },
                "event": "push",
                "actor": "ada<&>",
                "commit": {
                    "shortSha": "26713a8",
                    "message": "Run Automata's own CI",
                    "href": "https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4"
                },
                "createdAt": {
                    "iso": "2026-08-06T08:15:00Z",
                    "label": "6 Aug 2026, 08:15 UTC"
                },
                "durationLabel": "3m 18s"
            }],
            "pagination": {
                "previousHref": null,
                "nextHref": null,
                "label": "1 run"
            }
        }
    })
}

fn job_log_request(log_visibility: &str) -> Value {
    let mut request = valid_request();
    let live = if log_visibility == "full" {
        json!({
            "ticketHref": "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000/jobs/11111111-1111-4111-8111-111111111111/live-ticket",
            "state": "closed"
        })
    } else {
        Value::Null
    };
    request["page"] = json!({
        "kind": "job-log",
        "shell": {
            "productName": "Automata",
            "homeHref": "/repositories",
            "signIn": {
                "action": "/auth/github/login",
                "returnPath": "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000/jobs/11111111-1111-4111-8111-111111111111"
            },
            "signOut": null,
            "documentTitle": "Build logs · Automata",
            "description": "Job logs for Automata",
            "viewer": null,
            "navigation": [
                { "label": "Repositories", "href": "/repositories", "current": false },
                { "label": "Actions", "href": "/automata-ci/automata/actions", "current": true }
            ]
        },
        "repository": {
            "owner": "automata-ci",
            "name": "automata",
            "sourceHref": "https://github.com/automata-ci/automata",
            "runsHref": "/automata-ci/automata/actions",
            "settingsHref": null
        },
        "run": {
            "number": "1842",
            "name": "Build and test",
            "href": "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000",
            "workflowName": "CI",
            "workflowHref": "/automata-ci/automata/actions/workflows/22222222-2222-4222-8222-222222222222",
            "attempt": 1
        },
        "jobs": [{
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "Build",
            "href": "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000/jobs/11111111-1111-4111-8111-111111111111",
            "status": { "label": "Succeeded", "tone": "success" }
        }],
        "navigationPagination": {
            "previousHref": null,
            "nextHref": null,
            "label": "1 job"
        },
        "job": {
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "Build",
            "href": "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000/jobs/11111111-1111-4111-8111-111111111111",
            "attempt": 1,
            "runnerLabel": null,
            "status": { "label": "Succeeded", "tone": "success" },
            "startedAt": null,
            "durationLabel": null
        },
        "logVisibility": log_visibility,
        "live": live,
        "notice": null
    });
    request
}

fn repository_directory_request() -> Value {
    let assets = client_assets();
    json!({
        "schemaVersion": 1,
        "host": {
            "locale": "en",
            "cspNonce": "renderer-test-nonce",
            "assets": {
                "clientEntry": assets.script_path,
                "stylesheets": assets.stylesheet_paths,
            }
        },
        "page": {
            "kind": "repository-directory",
            "shell": {
                "productName": "Automata",
                "homeHref": "/repositories",
                "signIn": null,
                "signOut": {
                    "action": "/auth/logout",
                    "csrfToken": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
                },
                "documentTitle": "Repositories · Automata",
                "description": "Browse repositories available under your current access.",
                "viewer": { "displayName": "Ada" },
                "navigation": [
                    { "label": "Repositories", "href": "/repositories", "current": true }
                ]
            },
            "heading": "Repositories",
            "summary": "Browse repositories available under your current access.",
            "repositories": [
                {
                    "owner": "automata-ci",
                    "name": "automata",
                    "sourceHref": "https://github.com/automata-ci/automata",
                    "actionsHref": null,
                    "settingsHref": "/automata-ci/automata/settings/secrets"
                },
                {
                    "owner": "acme-labs",
                    "name": "payments-api",
                    "sourceHref": "https://github.com/acme-labs/payments-api",
                    "actionsHref": "/acme-labs/payments-api/actions",
                    "settingsHref": "/acme-labs/payments-api/settings/access"
                }
            ],
            "pagination": {
                "nextHref": null,
                "label": "2 repositories on this page"
            }
        }
    })
}

#[test]
fn renders_valid_input_escapes_data_and_recovers_after_rejection() {
    let renderer = WasmtimeRenderer::new(RenderPolicy::default()).expect("renderer initializes");
    let request = valid_request().to_string();

    let page = renderer.render(&request).expect("valid request renders");
    let html = page.as_str();
    assert!(html.starts_with("<!doctype html><html lang=\"en\">"));
    assert!(html.contains("&lt;script&gt;globalThis.compromised=true&lt;/script&gt;"));
    assert!(html.contains("ada&lt;&amp;&gt;"));
    assert!(!html.contains("<script>globalThis.compromised=true</script>"));
    assert!(html.contains("\\u003cscript\\u003eglobalThis.compromised=true\\u003c/script\\u003e"));

    let mut unsafe_request = valid_request();
    unsafe_request["host"]["assets"]["clientEntry"] = json!("https://evil.invalid/payload.js");
    assert_eq!(
        renderer.render(&unsafe_request.to_string()),
        Err(RenderError::GuestExecution)
    );

    let next_page = renderer
        .render(&request)
        .expect("a rejected guest never poisons subsequent instances");
    assert_eq!(next_page, page);
}

#[test]
fn repository_directory_accepts_only_exact_authenticated_settings_destinations() {
    let renderer = WasmtimeRenderer::new(RenderPolicy::default()).expect("renderer initializes");
    let request = repository_directory_request();

    let page = renderer
        .render(&request.to_string())
        .expect("exact repository settings destinations render");
    let html = page.as_str();
    assert!(html.contains("href=\"/automata-ci/automata/settings/secrets\""));
    assert!(html.contains("Secrets</a>"));
    assert!(html.contains("href=\"/acme-labs/payments-api/settings/access\""));
    assert!(html.contains("Access</a>"));

    let mut unsupported = request;
    unsupported["page"]["repositories"][0]["settingsHref"] =
        json!("/automata-ci/automata/settings");
    assert_eq!(
        renderer.render(&unsupported.to_string()),
        Err(RenderError::GuestExecution)
    );
}

#[test]
fn renders_current_job_log_visibility_contract() {
    let renderer = WasmtimeRenderer::new(RenderPolicy::default()).expect("renderer initializes");

    for visibility in ["full", "restricted"] {
        let html = renderer
            .render(&job_log_request(visibility).to_string())
            .expect("current job-log model renders");
        assert!(html.as_str().contains("Build logs · Automata"));
    }
}

#[test]
fn rejects_malformed_and_oversized_input_before_guest_execution() {
    let policy = RenderPolicy::builder()
        .max_input_bytes(64)
        .build()
        .expect("valid policy");
    let renderer = WasmtimeRenderer::new(policy).expect("renderer initializes");

    assert!(matches!(
        renderer.render("{not-json"),
        Err(RenderError::MalformedRequest { .. })
    ));
    assert_eq!(
        renderer.render(&" ".repeat(65)),
        Err(RenderError::InputTooLarge {
            actual_bytes: 65,
            max_bytes: 64,
        })
    );
}

#[test]
fn enforces_the_public_input_contract_in_utf8_bytes() {
    let renderer = WasmtimeRenderer::new(RenderPolicy::default()).expect("renderer initializes");
    let oversized = "😀".repeat(MAX_RENDER_REQUEST_UTF8_BYTES / 4 + 1);

    assert!(oversized.len() > MAX_RENDER_REQUEST_UTF8_BYTES);
    assert!(oversized.chars().count() < MAX_RENDER_REQUEST_UTF8_BYTES);
    assert_eq!(
        renderer.render(&oversized),
        Err(RenderError::InputTooLarge {
            actual_bytes: oversized.len(),
            max_bytes: MAX_RENDER_REQUEST_UTF8_BYTES,
        })
    );
}

#[test]
fn fuel_exhaustion_is_typed_and_fail_closed() {
    let policy = RenderPolicy::builder()
        .fuel(1)
        .build()
        .expect("valid policy");
    let renderer = WasmtimeRenderer::new(policy).expect("renderer initializes");

    assert_eq!(
        renderer.render(&valid_request().to_string()),
        Err(RenderError::ResourceExhausted(ResourceLimit::Fuel))
    );
}

#[test]
fn memory_exhaustion_is_typed_and_fail_closed() {
    let policy = RenderPolicy::builder()
        .max_total_memory_bytes(64 * 1024)
        .max_output_bytes(32 * 1024)
        .build()
        .expect("valid policy");
    let renderer = WasmtimeRenderer::new(policy).expect("renderer initializes");

    assert_eq!(
        renderer.render(&valid_request().to_string()),
        Err(RenderError::ResourceExhausted(ResourceLimit::Memory))
    );
}

#[test]
fn deadline_expiry_is_typed_and_fail_closed() {
    let policy = RenderPolicy::builder()
        .timeout(Duration::from_nanos(1))
        .epoch_tick(Duration::from_millis(1))
        .build()
        .expect("valid policy");
    let renderer = WasmtimeRenderer::new(policy).expect("renderer initializes");

    assert_eq!(
        renderer.render(&valid_request().to_string()),
        Err(RenderError::ResourceExhausted(ResourceLimit::Deadline))
    );
}

#[test]
fn rejects_oversized_output_at_the_component_lift_boundary() {
    let policy = RenderPolicy::builder()
        .max_output_bytes(128)
        .build()
        .expect("valid policy");
    let renderer = WasmtimeRenderer::new(policy).expect("renderer initializes");

    assert_eq!(
        renderer.render(&valid_request().to_string()),
        Err(RenderError::OutputTooLarge { max_bytes: 128 })
    );
}

#[test]
fn simultaneous_renders_observe_non_blocking_admission() {
    const WORKERS: usize = 16;

    let policy = RenderPolicy::builder()
        .max_concurrent_renders(1)
        .build()
        .expect("valid policy");
    let renderer = Arc::new(WasmtimeRenderer::new(policy).expect("renderer initializes"));
    let request = Arc::new(concurrent_valid_request().to_string());
    let barrier = Arc::new(Barrier::new(WORKERS + 1));

    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let renderer = Arc::clone(&renderer);
            let request = Arc::clone(&request);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                renderer.render(&request)
            })
        })
        .collect();

    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("render worker does not panic"))
        .collect();

    assert!(results.contains(&Err(RenderError::AtCapacity)));
    assert!(
        results.iter().any(Result::is_ok),
        "at least one admitted render must succeed: {results:?}"
    );
    assert!(
        results
            .iter()
            .all(|result| result.is_ok() || *result == Err(RenderError::AtCapacity))
    );
}

fn concurrent_valid_request() -> Value {
    let mut request = valid_request();
    let prototype = request["page"]["runs"][0].clone();
    request["page"]["runs"] = Value::Array(
        (0..8)
            .map(|index| {
                let mut run = prototype.clone();
                run["id"] = json!(format!("run-{index}"));
                run["href"] = json!(format!("/automata-ci/automata/actions/runs/{index}"));
                run
            })
            .collect(),
    );
    request
}
