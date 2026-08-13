use std::{error::Error, sync::Arc};

use automata_ci::app::{
    conformance_github_stub::HermeticGithubStubServer,
    conformance_shard::{ConformanceShardAdapterError, ProductConformanceShard},
};
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType, MemoryBlobStore,
};
use automata_ci_conformance::{
    GithubStubExchange, GithubStubRequest, GithubStubResponse, GithubStubScript, ShardPlan,
};
use automata_ci_postgres_test_support::PostgresTestHarness;
use bytes::Bytes;

fn product_shard(run: &str, ordinal: u16) -> ProductConformanceShard {
    let plan = ShardPlan::derive(run, ordinal + 1).expect("shard plan");
    ProductConformanceShard::from_plan(&plan, ordinal).expect("selected product shard")
}

#[tokio::test]
async fn product_shards_enforce_object_isolation() {
    let left = product_shard("product-shard-object-consumption", 0);
    let right = product_shard("product-shard-object-consumption", 1);
    let backing = MemoryBlobStore::default();
    let left_objects = left.blob_store(backing.clone()).expect("left object scope");
    let right_objects = right
        .blob_store(backing.clone())
        .expect("right object scope");

    let media_type = MediaType::new("application/octet-stream").expect("media type");
    let (_, left_descriptor) = left_objects
        .put_provider(
            "results/output.bin",
            media_type.clone(),
            Bytes::from_static(b"left"),
        )
        .await
        .expect("left write");
    let (_, right_descriptor) = right_objects
        .put_provider(
            "results/output.bin",
            media_type,
            Bytes::from_static(b"right"),
        )
        .await
        .expect("right write");
    assert_ne!(
        left_descriptor.key().as_str(),
        right_descriptor.key().as_str()
    );
    assert!(
        left_descriptor
            .key()
            .as_str()
            .starts_with(left.identity().object_prefix())
    );
    assert!(matches!(
        left_objects
            .get_provider_verified(&right_descriptor, right_descriptor.size())
            .await,
        Err(ConformanceShardAdapterError::ForeignObjectDescriptor)
    ));
    assert_eq!(
        left_objects
            .get_provider_verified(&left_descriptor, left_descriptor.size())
            .await
            .expect("left verified read")
            .bytes()
            .as_ref(),
        b"left"
    );
    let injectable: Arc<dyn ImmutableBlobStore> = Arc::new(
        left.blob_store(backing.clone())
            .expect("injectable object scope"),
    );
    let injected_payload = BlobPayload::from_bytes(
        BlobKey::new("results/injected.bin").expect("ordinary product key"),
        MediaType::new("application/octet-stream").expect("media type"),
        Bytes::from_static(b"injected"),
    );
    let injected_descriptor = injected_payload.descriptor().clone();
    injectable
        .put_if_absent(injected_payload)
        .await
        .expect("trait-injected logical write");
    let verified = injectable
        .get_verified(&injected_descriptor, injected_descriptor.size())
        .await
        .expect("trait-injected logical read");
    assert_eq!(verified.descriptor(), &injected_descriptor);
    assert_eq!(verified.bytes().as_ref(), b"injected");
    let already_prefixed = BlobPayload::from_bytes(
        left_objects
            .provider_key("results/already-prefixed.bin")
            .expect("provider key"),
        MediaType::new("application/octet-stream").expect("media type"),
        Bytes::from_static(b"ambiguous"),
    );
    let already_prefixed_descriptor = already_prefixed.descriptor().clone();
    let error = injectable
        .put_if_absent(already_prefixed)
        .await
        .expect_err("logical boundary must reject an already-scoped key");
    assert_eq!(error.kind(), BlobStoreErrorKind::Unauthorized);
    assert!(matches!(
        left_objects.provider_key(left_descriptor.key().as_str()),
        Err(ConformanceShardAdapterError::InvalidRelativeObjectKey)
    ));
    let error = injectable
        .get_verified(
            &already_prefixed_descriptor,
            already_prefixed_descriptor.size(),
        )
        .await
        .expect_err("logical read must reject an already-scoped key");
    assert_eq!(error.kind(), BlobStoreErrorKind::Unauthorized);
}

#[tokio::test]
async fn product_shard_credential_is_consumed_by_the_hermetic_server() {
    let shard = product_shard("product-shard-credential-consumption", 0);
    let credential_id = format!("{}:installation-42", shard.identity().credential_scope());
    let credential = shard
        .hermetic_github_credential(
            "installation-42",
            SecretString::new("Bearer shard-secret").expect("authorization"),
        )
        .expect("scoped credential");
    assert_eq!(credential.id(), credential_id);
    let debug = format!("{credential:?}");
    assert!(!debug.contains("shard-secret"));
    assert!(debug.contains("[REDACTED]"));
    let server = HermeticGithubStubServer::start(
        GithubStubScript::new(vec![GithubStubExchange {
            request: GithubStubRequest {
                method: "GET".to_owned(),
                path_and_query: "/credential-scope".to_owned(),
                body_sha256: None,
                credential_id: Some(credential.id().to_owned()),
            },
            response: GithubStubResponse::Page {
                status: 200,
                body: b"scoped".to_vec(),
                next: None,
            },
        }])
        .expect("credential-scope script"),
        vec![credential],
    )
    .await
    .expect("credential consumed by real adapter");
    let response = reqwest::Client::new()
        .get(format!("{}/credential-scope", server.origin()))
        .header(reqwest::header::AUTHORIZATION, "Bearer shard-secret")
        .send()
        .await
        .expect("scoped request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.bytes().await.expect("response body"), "scoped");
    server
        .finish()
        .await
        .expect("credential-scope script complete");
}

#[tokio::test]
async fn product_shards_hold_distinct_single_use_loopback_reservations() {
    let left = product_shard("product-shard-port-consumption", 0);
    let independently_selected_left = product_shard("product-shard-port-consumption", 0);
    let right = product_shard("product-shard-port-consumption", 1);
    let left_port = left
        .reserve_loopback_port("control-plane")
        .await
        .expect("left port");
    let right_port = right
        .reserve_loopback_port("control-plane")
        .await
        .expect("right port");
    assert!(left_port.local_addr().ip().is_loopback());
    assert_ne!(left_port.local_addr(), right_port.local_addr());
    assert_eq!(
        left_port.reservation_id(),
        format!("{}:control-plane", left.identity().port_reservation_key())
    );
    assert_eq!(
        right_port.reservation_id(),
        format!("{}:control-plane", right.identity().port_reservation_key())
    );
    assert!(matches!(
        independently_selected_left
            .reserve_loopback_port("control-plane")
            .await,
        Err(ConformanceShardAdapterError::DuplicatePortReservation)
    ));
    let occupied = left_port.local_addr();
    assert!(tokio::net::TcpListener::bind(occupied).await.is_err());
    drop(left_port.into_listener());
    let rebound = tokio::net::TcpListener::bind(occupied)
        .await
        .expect("reservation releases only when listener is dropped");
    drop(rebound);
    assert!(matches!(
        left.reserve_loopback_port("control-plane").await,
        Err(ConformanceShardAdapterError::DuplicatePortReservation)
    ));
}

#[tokio::test]
async fn shard_object_scope_rejects_escape_and_foreign_backing_objects() {
    let shard = product_shard("object-scope-rejection", 0);
    let backing = MemoryBlobStore::default();
    let scoped = shard.blob_store(backing.clone()).expect("object scope");
    for invalid in ["", "/absolute", "../escape", "nested/../../escape"] {
        assert!(
            scoped.provider_key(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }

    let foreign_payload = BlobPayload::from_bytes(
        BlobKey::new("conformance/v1/foreign/000/result").expect("foreign key"),
        MediaType::new("application/octet-stream").expect("media type"),
        Bytes::from_static(b"foreign"),
    );
    let foreign_descriptor = foreign_payload.descriptor().clone();
    backing
        .put_if_absent(foreign_payload)
        .await
        .expect("foreign backing object");
    assert!(matches!(
        scoped
            .get_provider_verified(&foreign_descriptor, foreign_descriptor.size())
            .await,
        Err(ConformanceShardAdapterError::ForeignObjectDescriptor)
    ));

    assert!(matches!(
        shard.hermetic_github_credential(
            "not/canonical",
            SecretString::new("Bearer value").expect("secret")
        ),
        Err(ConformanceShardAdapterError::InvalidLocalIdentity)
    ));
    assert!(matches!(
        shard.reserve_loopback_port("not/canonical").await,
        Err(ConformanceShardAdapterError::InvalidLocalIdentity)
    ));
}

#[tokio::test]
async fn transparent_product_keys_are_isolated_and_preserve_logical_descriptors() {
    let backing = MemoryBlobStore::default();
    let left_shard = product_shard("transparent-product-object-scope", 0);
    let right_shard = product_shard("transparent-product-object-scope", 1);
    let left = left_shard
        .blob_store(backing.clone())
        .expect("left transparent scope");
    let right = right_shard
        .blob_store(backing.clone())
        .expect("right transparent scope");
    let logical_key = BlobKey::new("workflow-admission/plans/v1/plan.json")
        .expect("ordinary workflow-service key");
    let media_type = MediaType::new("application/json").expect("media type");
    let left_payload = BlobPayload::from_bytes(
        logical_key.clone(),
        media_type.clone(),
        Bytes::from_static(br#"{"shard":"left"}"#),
    );
    let right_payload = BlobPayload::from_bytes(
        logical_key,
        media_type,
        Bytes::from_static(br#"{"shard":"right"}"#),
    );
    let left_descriptor = left_payload.descriptor().clone();
    let right_descriptor = right_payload.descriptor().clone();

    left.put_if_absent(left_payload)
        .await
        .expect("left product write");
    right
        .put_if_absent(right_payload)
        .await
        .expect("right product write");
    let left_verified = left
        .get_verified(&left_descriptor, left_descriptor.size())
        .await
        .expect("left product read");
    let right_verified = right
        .get_verified(&right_descriptor, right_descriptor.size())
        .await
        .expect("right product read");
    assert_eq!(left_verified.descriptor(), &left_descriptor);
    assert_eq!(right_verified.descriptor(), &right_descriptor);
    assert_eq!(left_verified.bytes().as_ref(), br#"{"shard":"left"}"#);
    assert_eq!(right_verified.bytes().as_ref(), br#"{"shard":"right"}"#);
    assert_ne!(
        left.provider_key("workflow-admission/plans/v1/plan.json")
            .expect("left provider key"),
        right
            .provider_key("workflow-admission/plans/v1/plan.json")
            .expect("right provider key")
    );
    let other_shard_prefixed = BlobPayload::from_bytes(
        right
            .provider_key("results/v7/already-prefixed")
            .expect("right provider key"),
        MediaType::new("application/octet-stream").expect("media type"),
        Bytes::from_static(b"ambiguous"),
    );
    let error = left
        .put_if_absent(other_shard_prefixed)
        .await
        .expect_err("a foreign shard prefix is not a logical product key");
    assert_eq!(error.kind(), BlobStoreErrorKind::Unauthorized);

    let foreign_payload = BlobPayload::from_bytes(
        BlobKey::new("foreign/results/v7/manifest").expect("foreign provider key"),
        MediaType::new("application/json").expect("media type"),
        Bytes::from_static(b"{}"),
    );
    let foreign_descriptor = foreign_payload.descriptor().clone();
    backing
        .put_if_absent(foreign_payload)
        .await
        .expect("foreign provider object");
    let error = left
        .get_verified(&foreign_descriptor, foreign_descriptor.size())
        .await
        .expect_err("foreign provider object is not visible at the logical boundary");
    assert_eq!(error.kind(), BlobStoreErrorKind::NotFound);
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL pointing to PostgreSQL 18+"]
async fn shard_postgres_schema_is_real_isolated_and_marker_owned()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let harness = PostgresTestHarness::from_environment()?;
    harness
        .run_with_empty_database(|database| async move {
            let left = product_shard("postgres-shard-consumption", 0);
            let right = product_shard("postgres-shard-consumption", 1);
            let left_schema = left.provision_postgres_schema(database.pool()).await?;
            let right_schema = right.provision_postgres_schema(database.pool()).await?;
            assert_eq!(left_schema.name(), left.identity().postgres_schema());
            assert_eq!(right_schema.name(), right.identity().postgres_schema());
            assert_ne!(left_schema.name(), right_schema.name());

            let mut left_transaction = left_schema.begin_isolated().await?;
            let left_search_path: String = sqlx::query_scalar("SHOW search_path")
                .fetch_one(&mut *left_transaction)
                .await?;
            assert_eq!(
                left_search_path,
                format!("{}, pg_catalog, pg_temp", left_schema.name())
            );
            sqlx::query("CREATE TABLE shard_value (value TEXT NOT NULL)")
                .execute(&mut *left_transaction)
                .await?;
            sqlx::query("INSERT INTO shard_value (value) VALUES ('left')")
                .execute(&mut *left_transaction)
                .await?;
            left_transaction.commit().await?;

            let mut right_transaction = right_schema.begin_isolated().await?;
            sqlx::query("CREATE TABLE shard_value (value TEXT NOT NULL)")
                .execute(&mut *right_transaction)
                .await?;
            sqlx::query("INSERT INTO shard_value (value) VALUES ('right')")
                .execute(&mut *right_transaction)
                .await?;
            right_transaction.commit().await?;

            let mut left_transaction = left_schema.begin_isolated().await?;
            let left_value: String = sqlx::query_scalar("SELECT value FROM shard_value")
                .fetch_one(&mut *left_transaction)
                .await?;
            left_transaction.rollback().await?;
            let mut right_transaction = right_schema.begin_isolated().await?;
            let right_value: String = sqlx::query_scalar("SELECT value FROM shard_value")
                .fetch_one(&mut *right_transaction)
                .await?;
            right_transaction.rollback().await?;
            assert_eq!(left_value, "left");
            assert_eq!(right_value, "right");

            assert!(matches!(
                left.provision_postgres_schema(database.pool()).await,
                Err(ConformanceShardAdapterError::PostgresSchemaOccupied)
            ));
            left_schema.cleanup().await?;
            right_schema.cleanup().await?;
            for name in [
                left.identity().postgres_schema(),
                right.identity().postgres_schema(),
            ] {
                let remains: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1)",
                )
                .bind(name)
                .fetch_one(database.pool())
                .await?;
                assert!(!remains, "schema {name} survived exact cleanup");
            }
            Ok(())
        })
        .await?;
    Ok(())
}
