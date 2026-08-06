/// Embedded migrations make the statically linked control plane self-contained.
pub(crate) static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
