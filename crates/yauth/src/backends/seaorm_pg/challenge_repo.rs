use sea_orm::prelude::*;
use sea_orm::sea_query::{Expr, ExprTrait, OnConflict};
use sea_orm::{ConnectionTrait, Insert, Schema, Set, UpdateMany};

use super::entities::challenges;
use super::sea_err;
use crate::repo::{ChallengeRepository, RepoError, RepoFuture, sealed};

pub(crate) struct SeaOrmChallengeRepo {
    db: DatabaseConnection,
    initialized: tokio::sync::OnceCell<()>,
}

impl SeaOrmChallengeRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            initialized: tokio::sync::OnceCell::const_new(),
        }
    }

    async fn ensure_init(&self) -> Result<(), RepoError> {
        self.initialized
            .get_or_try_init(|| async {
                let schema = Schema::new(self.db.get_database_backend());
                let stmt = schema
                    .create_table_from_entity(challenges::Entity)
                    .if_not_exists()
                    .to_owned();
                let builder = self.db.get_database_backend();
                self.db
                    .execute_unprepared(&builder.build(&stmt).to_string())
                    .await
                    .map_err(sea_err)?;
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

/// The claim statement: `INSERT … ON CONFLICT DO UPDATE … WHERE expires_at <= now`.
///
/// Built here rather than inline in [`SeaOrmChallengeRepo::try_claim_challenge`]
/// so the SQL pin in this module's tests asserts on the statement the repository
/// actually executes. Asserting on a second, hand-copied builder would leave the
/// production one free to lose its `WHERE` — the one clause the whole guarantee
/// rests on — with the test still green.
fn claim_insert(
    key: String,
    value: serde_json::Value,
    expires_at: DateTimeWithTimeZone,
    now: DateTimeWithTimeZone,
) -> Insert<challenges::ActiveModel> {
    challenges::Entity::insert(challenges::ActiveModel {
        key: Set(key),
        value: Set(value),
        expires_at: Set(expires_at),
    })
    .on_conflict(
        OnConflict::column(challenges::Column::Key)
            .update_columns([challenges::Column::Value, challenges::Column::ExpiresAt])
            .action_and_where(
                Expr::col((challenges::Entity, challenges::Column::ExpiresAt)).lte(now),
            )
            .to_owned(),
    )
}

fn live_challenge_update(
    key: String,
    value: serde_json::Value,
    now: DateTimeWithTimeZone,
) -> UpdateMany<challenges::Entity> {
    challenges::Entity::update_many()
        .col_expr(challenges::Column::Value, Expr::value(value))
        .filter(challenges::Column::Key.eq(key))
        .filter(challenges::Column::ExpiresAt.gt(now))
}

impl sealed::Sealed for SeaOrmChallengeRepo {}

impl ChallengeRepository for SeaOrmChallengeRepo {
    fn set_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            // Cleanup expired
            challenges::Entity::delete_many()
                .filter(challenges::Column::ExpiresAt.lt(chrono::Utc::now().fixed_offset()))
                .exec(&self.db)
                .await
                .ok();

            let expires_at =
                chrono::Utc::now().fixed_offset() + chrono::Duration::seconds(ttl_secs as i64);

            let model = challenges::ActiveModel {
                key: Set(key),
                value: Set(value),
                expires_at: Set(expires_at),
            };

            challenges::Entity::insert(model)
                .on_conflict(
                    OnConflict::column(challenges::Column::Key)
                        .update_columns([challenges::Column::Value, challenges::Column::ExpiresAt])
                        .to_owned(),
                )
                .exec(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(())
        })
    }

    fn get_challenge(&self, key: &str) -> RepoFuture<'_, Option<serde_json::Value>> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let row = challenges::Entity::find_by_id(&key)
                .filter(challenges::Column::ExpiresAt.gt(chrono::Utc::now().fixed_offset()))
                .one(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(row.map(|m| m.value))
        })
    }

    fn delete_challenge(&self, key: &str) -> RepoFuture<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            challenges::Entity::delete_many()
                .filter(challenges::Column::Key.eq(&key))
                .exec(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(())
        })
    }

    fn update_challenge_if_live(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> RepoFuture<'_, bool> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            // UPDATE cannot recreate a row deleted by a concurrent request.
            // Do not write expires_at: an attempt never renews the challenge.
            let result = live_challenge_update(key, value, chrono::Utc::now().fixed_offset())
                .exec(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(result.rows_affected > 0)
        })
    }

    /// Atomic: one [`claim_insert`] statement.
    ///
    /// Postgres takes a row lock on the conflicting tuple before evaluating the
    /// `DO UPDATE` predicate, so of two concurrent claims exactly one can find
    /// the row claimable. The claim is reported by `rows_affected`: the insert
    /// path and the expired-row update path both report 1, a live row reports 0
    /// because the predicate excluded it.
    ///
    /// No expired-row sweep here, unlike `set_challenge` — the predicate already
    /// reuses an expired row in place, and a claim is on the login hot path.
    fn try_claim_challenge(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> RepoFuture<'_, bool> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let now = chrono::Utc::now().fixed_offset();
            let expires_at = now + chrono::Duration::seconds(ttl_secs as i64);

            let rows_affected = claim_insert(key, value, expires_at, now)
                .exec_without_returning(&self.db)
                .await
                .map_err(sea_err)?;

            Ok(rows_affected > 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sea_orm::QueryTrait;

    use super::*;

    #[test]
    fn the_update_never_inserts_or_changes_the_expiry() {
        let sql = live_challenge_update(
            "pending-test".into(),
            serde_json::json!({ "attempts": 1 }),
            chrono::Utc::now().fixed_offset(),
        )
        .build(sea_orm::DatabaseBackend::Postgres)
        .to_string();

        let (update, predicate) = sql.split_once(" WHERE ").expect("conditional update");
        assert!(
            update.starts_with(r#"UPDATE "yauth_challenges" SET "value" ="#),
            "{sql}"
        );
        assert!(
            !update.contains("expires_at"),
            "the original deadline must not change: {sql}"
        );
        assert!(predicate.contains(r#""key" = 'pending-test'"#), "{sql}");
        assert!(predicate.contains(r#""expires_at" >"#), "{sql}");
    }

    /// The claim's whole value is in the SQL: without the `WHERE` on the
    /// conflict action the statement is an unconditional upsert whose
    /// `rows_affected` is always 1, so every racer would believe it won.
    ///
    /// Asserted on [`claim_insert`] itself — the same builder
    /// `try_claim_challenge` executes — so dropping the predicate from the
    /// repository turns this test red.
    #[test]
    fn the_claim_upserts_only_over_an_expired_row() {
        let now = chrono::Utc::now().fixed_offset();
        let sql = claim_insert(
            "mfa_totp_used:x".to_owned(),
            serde_json::json!({ "used": true }),
            now + chrono::Duration::seconds(120),
            now,
        )
        .build(sea_orm::DatabaseBackend::Postgres)
        .to_string();

        assert!(
            sql.contains(r#"ON CONFLICT ("key") DO UPDATE"#),
            "expected a conflict action, got: {sql}"
        );
        assert!(
            sql.contains(r#"WHERE "yauth_challenges"."expires_at" <="#),
            "the conflict action must be gated on the stored row being expired, got: {sql}"
        );
        assert!(
            !sql.contains("RETURNING"),
            "the claim is executed for its row count, not a returned row: {sql}"
        );
    }

    /// A live connection, or `None` so the two cases below self-skip.
    ///
    /// Same env-var convention as `tests/repo_conformance.rs`'s seaorm-pg
    /// backend. The claim's exclusivity is a property of Postgres' row locking
    /// under `ON CONFLICT DO UPDATE`, so unlike the SQL pin above these cannot
    /// be asserted without a server; run them with
    /// `SEAORM_PG_DATABASE_URL=postgres://…` (or `DATABASE_URL`).
    async fn live_repo() -> Option<Arc<SeaOrmChallengeRepo>> {
        let url = std::env::var("SEAORM_PG_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        let mut opts = sea_orm::ConnectOptions::new(url);
        opts.max_connections(16)
            .min_connections(1)
            .sqlx_logging(false);
        match sea_orm::Database::connect(opts).await {
            Ok(db) => {
                let repo = SeaOrmChallengeRepo::new(db);
                // Create the table before any concurrency below, and tolerate
                // losing the creation race: Postgres' `CREATE TABLE IF NOT
                // EXISTS` is not atomic against a concurrent creator, and two
                // `#[tokio::test]`s each open their own connection, so the loser
                // sees a 23505 on `pg_type_typname_nsp_index`. `ensure_init`
                // caches success only, so a retry finds the winner's table.
                let mut attempt = 0;
                loop {
                    match repo.ensure_init().await {
                        Ok(()) => break,
                        Err(e) if attempt < 4 => {
                            attempt += 1;
                            eprintln!("challenge table creation retry {attempt}: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        Err(e) => panic!("challenge table: {e}"),
                    }
                }
                Some(Arc::new(repo))
            }
            Err(e) => {
                eprintln!("seaorm-pg connection failed: {e}, skipping");
                None
            }
        }
    }

    /// A key no other run (or other test in this run) can collide with, so the
    /// cases below leave a shared database exactly as they found it.
    fn scratch_key() -> String {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("yauth_test_claim:{nanos}:{seq}")
    }

    #[tokio::test]
    async fn live_claim_is_exclusive_and_expiry_aware() {
        let Some(repo) = live_repo().await else {
            eprintln!("no SEAORM_PG_DATABASE_URL/DATABASE_URL, skipping");
            return;
        };
        let key = scratch_key();

        assert!(
            repo.try_claim_challenge(&key, serde_json::json!(1), 120)
                .await
                .unwrap(),
            "the first claim of a free key must win"
        );
        assert!(
            !repo
                .try_claim_challenge(&key, serde_json::json!(2), 120)
                .await
                .unwrap(),
            "a live row must refuse a second claim"
        );
        assert_eq!(
            repo.get_challenge(&key).await.unwrap(),
            Some(serde_json::json!(1)),
            "the refused claim must not have overwritten the winner's value"
        );

        // An expired row is claimable in place: TTL 0 writes `expires_at = now`,
        // which the conflict predicate reads as expired on the next call.
        repo.set_challenge(&key, serde_json::json!("stale"), 0)
            .await
            .unwrap();
        assert!(
            repo.try_claim_challenge(&key, serde_json::json!(3), 120)
                .await
                .unwrap(),
            "an expired row must be claimable"
        );
        assert_eq!(
            repo.get_challenge(&key).await.unwrap(),
            Some(serde_json::json!(3))
        );

        repo.delete_challenge(&key).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_only_one_of_many_concurrent_claims_wins() {
        let Some(repo) = live_repo().await else {
            eprintln!("no SEAORM_PG_DATABASE_URL/DATABASE_URL, skipping");
            return;
        };
        let key = scratch_key();

        // Each task takes its own pooled connection, so these are genuinely
        // concurrent transactions contending for one row — the situation
        // `get_challenge` + `set_challenge` cannot survive and this statement
        // must (review finding 4).
        let claimants = 8;
        let mut tasks = Vec::with_capacity(claimants);
        for claimant in 0..claimants {
            let repo = repo.clone();
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                repo.try_claim_challenge(&key, serde_json::json!(claimant), 120)
                    .await
                    .unwrap()
            }));
        }

        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "exactly one of {claimants} concurrent claims may win, got {winners}"
        );

        repo.delete_challenge(&key).await.unwrap();
    }
}
