use toasty::Db;

use crate::entities::YauthAuditLog;
use crate::helpers::{chrono_to_jiff, jiff_to_chrono, toasty_err};
use yauth::repo::{AuditLogFilter, AuditLogRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyAuditLogRepo {
    db: Db,
}

impl ToastyAuditLogRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyAuditLogRepo {}

impl AuditLogRepository for ToastyAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            toasty::create!(YauthAuditLog {
                id: input.id,
                user_id: input.user_id,
                event_type: input.event_type,
                metadata: input.metadata,
                ip_address: input.ip_address,
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn list(
        &self,
        filter: AuditLogFilter,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, Vec<domain::AuditLog>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // Toasty currently lacks rich query DSL parity with sea_orm/diesel
            // for chained predicates + ordering, so we pull all rows and
            // filter/sort in application code. Audit log volumes are bounded
            // enough for this to work in practice; revisit if a concrete
            // scale issue surfaces.
            let mut all: Vec<YauthAuditLog> = YauthAuditLog::all()
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            all.retain(|r| {
                filter.user_id.is_none_or(|u| r.user_id == Some(u))
                    && filter
                        .event_type
                        .as_deref()
                        .is_none_or(|t| r.event_type == t)
            });
            all.sort_by_key(|r| std::cmp::Reverse(r.created_at));
            let start = offset.max(0) as usize;
            let take = limit.max(0) as usize;
            Ok(all
                .into_iter()
                .skip(start)
                .take(take)
                .map(|r| domain::AuditLog {
                    id: r.id,
                    user_id: r.user_id,
                    event_type: r.event_type,
                    metadata: r.metadata,
                    ip_address: r.ip_address,
                    created_at: jiff_to_chrono(r.created_at),
                })
                .collect())
        })
    }
}
