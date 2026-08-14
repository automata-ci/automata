//! Public, bounded capability discovery for one hosted Core shard.

use std::time::{SystemTime, UNIX_EPOCH};

use automata_ci_provisioning::ShardId;
use axum::{
    Json, Router,
    extract::State,
    http::header::CACHE_CONTROL,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::build_info::BuildInfo;

/// Stable discovery endpoint consumed before Cloud admits a shard.
pub const SHARD_CAPABILITIES_PATH: &str = "/internal/v1/capabilities";

const CAPABILITY_DOCUMENT_VERSION: u8 = 1;
const CORE_HTTP_PROTOCOL_VERSION: u8 = 1;
const MANAGEMENT_GRPC_PROTOCOL_VERSION: u8 = 1;
const DELEGATED_ACTOR_PROTOCOL_VERSION: u8 = 1;

#[derive(Clone, Debug)]
struct ShardCapabilitiesState {
    shard_id: String,
}

#[derive(Debug, Serialize)]
struct ShardCapabilities {
    protocol_version: u8,
    shard_id: String,
    release: BuildInfo,
    protocols: Protocols,
    public_endpoints: PublicEndpoints,
    server_time_ms: i64,
}

#[derive(Debug, Serialize)]
struct Protocols {
    core_http: [u8; 1],
    management_grpc: [u8; 1],
    delegated_actor: [u8; 1],
}

#[derive(Debug, Serialize)]
struct PublicEndpoints {}

/// Builds the unauthenticated discovery surface for a configured hosted shard.
pub(crate) fn router(shard_id: &ShardId) -> Router {
    Router::new()
        .route(SHARD_CAPABILITIES_PATH, get(capabilities))
        .with_state(ShardCapabilitiesState {
            shard_id: shard_id.as_str().to_owned(),
        })
}

async fn capabilities(State(state): State<ShardCapabilitiesState>) -> Response {
    (
        [(CACHE_CONTROL, "no-store")],
        Json(ShardCapabilities {
            protocol_version: CAPABILITY_DOCUMENT_VERSION,
            shard_id: state.shard_id,
            release: BuildInfo::current(),
            protocols: Protocols {
                core_http: [CORE_HTTP_PROTOCOL_VERSION],
                management_grpc: [MANAGEMENT_GRPC_PROTOCOL_VERSION],
                delegated_actor: [DELEGATED_ACTOR_PROTOCOL_VERSION],
            },
            public_endpoints: PublicEndpoints {},
            server_time_ms: unix_time_millis(),
        }),
    )
        .into_response()
}

fn unix_time_millis() -> i64 {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(milliseconds).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::Value;
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn document_identifies_shard_and_only_advertises_implemented_protocols() {
        let shard_id = ShardId::new("eu-test-1").expect("shard id");
        let response = router(&shard_id)
            .oneshot(
                Request::builder()
                    .uri(SHARD_CAPABILITIES_PATH)
                    .body(Body::empty())
                    .expect("capability request"),
            )
            .await
            .expect("capability response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");

        let document: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), 16 * 1024)
                .await
                .expect("bounded body"),
        )
        .expect("JSON response");
        assert_eq!(document["protocol_version"], CAPABILITY_DOCUMENT_VERSION);
        assert_eq!(document["shard_id"], "eu-test-1");
        assert_eq!(document["release"]["version"], BuildInfo::current().version);
        assert_eq!(document["release"]["commit"], BuildInfo::current().commit);
        assert_eq!(
            document["protocols"],
            serde_json::json!({
                "core_http": [CORE_HTTP_PROTOCOL_VERSION],
                "management_grpc": [MANAGEMENT_GRPC_PROTOCOL_VERSION],
                "delegated_actor": [DELEGATED_ACTOR_PROTOCOL_VERSION]
            })
        );
        assert_eq!(document["public_endpoints"], serde_json::json!({}));
        assert!(
            document["server_time_ms"]
                .as_i64()
                .is_some_and(|value| value > 0)
        );
    }

    #[tokio::test]
    async fn document_rejects_non_get_methods_without_redirecting() {
        let shard_id = ShardId::new("eu-test-1").expect("shard id");
        let response = router(&shard_id)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(SHARD_CAPABILITIES_PATH)
                    .body(Body::empty())
                    .expect("capability request"),
            )
            .await
            .expect("capability response");

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
