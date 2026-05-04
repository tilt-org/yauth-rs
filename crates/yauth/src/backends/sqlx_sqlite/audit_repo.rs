use sqlx::SqlitePool;

use crate::backends::sqlx_common::{
    dt_to_str, opt_str_to_json, opt_str_to_uuid, sqlx_err, str_to_dt,
};
use crate::domain;
use crate::repo::{AuditLogFilter, AuditLogRepository, RepoFuture, sealed};

pub(crate) struct SqlxSqliteAuditLogRepo {
    pool: SqlitePool,
}

impl SqlxSqliteAuditLogRepo {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxSqliteAuditLogRepo {}

impl AuditLogRepository for SqlxSqliteAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.map(|u| u.to_string());
            let metadata_str = input.metadata.map(|v| v.to_string());
            let created_str = dt_to_str(input.created_at);
            sqlx::query!(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?) /* sqlite */",
                id_str,
                user_id_str,
                input.event_type,
                metadata_str,
                input.ip_address,
                created_str,
            )
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
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
            let user_id_str = filter.user_id.map(|u| u.to_string());
            let event_type = filter.event_type;
            let rows = sqlx::query!(
                "SELECT id, user_id, event_type, metadata, ip_address, created_at \
                 FROM yauth_audit_log \
                 WHERE (?1 IS NULL OR user_id = ?1) \
                   AND (?2 IS NULL OR event_type = ?2) \
                 ORDER BY created_at DESC \
                 LIMIT ?3 OFFSET ?4 /* sqlite */",
                user_id_str,
                event_type,
                limit,
                offset,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
            Ok(rows
                .into_iter()
                .map(|r| domain::AuditLog {
                    id: r
                        .id
                        .as_deref()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_default(),
                    user_id: opt_str_to_uuid(r.user_id),
                    event_type: r.event_type,
                    metadata: opt_str_to_json(r.metadata),
                    ip_address: r.ip_address,
                    created_at: str_to_dt(&r.created_at),
                })
                .collect())
        })
    }
}
