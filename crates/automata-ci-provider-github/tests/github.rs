//! Hermetic GitHub adapter integration tests.

mod support;

mod api_transport;
mod changed_files;
mod checks;
mod common_changed_files;
mod configuration;
mod delivery_adapter;
mod event_envelope;
mod factory;
mod memberships;
mod oauth_flows;
mod repository_snapshots;
mod stored_push_rehydration;
mod webhook_event_normalization;
mod webhook_verification;
mod workflow_permissions;
