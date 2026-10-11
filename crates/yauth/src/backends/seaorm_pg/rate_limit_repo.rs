use sea_orm::prelude::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ConnectionTrait, DbErr, QuerySelect, Schema, Set, TransactionTrait};

use super::entities::rate_limits;
use super::sea_err;
use crate::domain;
use crate::repo::{RateLimitRepository, RepoError, RepoFuture, sealed};

pub(crate) struct SeaOrmRateLimitRepo {
    db: DatabaseConnection,
    initialized: tokio::sync::OnceCell<()>,
}

impl SeaOrmRateLimitRepo {
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
                    .create_table_from_entity(rate_limits::Entity)
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

impl sealed::Sealed for SeaOrmRateLimitRepo {}

impl RateLimitRepository for SeaOrmRateLimitRepo {
    fn check_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> RepoFuture<'_, domain::RateLimitResult> {
        let key = key.to_string();
        Box::pin(async move {
            self.ensure_init().await?;

            let window = i64::try_from(window_secs)
                .ok()
                .and_then(chrono::Duration::try_seconds)
                .filter(|window| *window > chrono::Duration::zero())
                .ok_or_else(|| RepoError::Internal("invalid rate-limit window".into()))?;
            if limit > i32::MAX as u32 {
                return Err(RepoError::Internal("invalid rate-limit capacity".into()));
            }
            let txn = self.db.begin().await.map_err(sea_err)?;

            // The insert also serializes competing first requests. A conflict
            // is expected; every other insertion failure must stop admission.
            let insert = rate_limits::Entity::insert(rate_limits::ActiveModel {
                key: Set(key.clone()),
                count: Set(0),
                window_start: Set(chrono::Utc::now().fixed_offset()),
            })
            .on_conflict(
                OnConflict::column(rate_limits::Column::Key)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&txn)
            .await;
            match insert {
                Ok(_) | Err(DbErr::RecordNotInserted) => {}
                Err(error) => return Err(sea_err(error)),
            }

            let row = rate_limits::Entity::find_by_id(&key)
                .lock_exclusive()
                .one(&txn)
                .await
                .map_err(sea_err)?
                .ok_or(RepoError::NotFound)?;
            if row.count < 0 {
                return Err(RepoError::Internal("invalid rate-limit counter".into()));
            }
            // Evaluate expiry only after acquiring the row lock: waiting for
            // another request must not resurrect an expired window.
            let now = chrono::Utc::now();
            let mut window_start = row.window_start.with_timezone(&chrono::Utc);
            let mut window_end = window_start
                .checked_add_signed(window)
                .ok_or_else(|| RepoError::Internal("invalid rate-limit expiry".into()))?;
            let mut count = row.count as u32;
            if window_end <= now {
                window_start = now;
                window_end = now
                    .checked_add_signed(window)
                    .ok_or_else(|| RepoError::Internal("invalid rate-limit expiry".into()))?;
                count = 0;
            }
            let allowed = count < limit;
            if allowed {
                count += 1;
                let mut active: rate_limits::ActiveModel = row.into();
                active.count = Set(count as i32);
                active.window_start = Set(window_start.fixed_offset());
                active.update(&txn).await.map_err(sea_err)?;
            }
            // Refusals do not grow the counter or extend its expiry. The
            // configured N requests are all admitted; request N+1 is refused.
            txn.commit().await.map_err(sea_err)?;
            Ok(domain::RateLimitResult {
                allowed,
                remaining: limit.saturating_sub(count),
                retry_after: if allowed {
                    0
                } else {
                    (window_end - now).num_seconds().max(1) as u64
                },
            })
        })
    }
}
