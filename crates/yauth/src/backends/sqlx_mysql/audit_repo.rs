use sqlx::MySqlPool;

use crate::backends::sqlx_common::sqlx_err;
use crate::domain;
use crate::repo::{AuditLogFilter, AuditLogRepository, RepoFuture, sealed};

pub(crate) struct SqlxMysqlAuditLogRepo {
    pool: MySqlPool,
}

impl SqlxMysqlAuditLogRepo {
    pub(crate) fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for SqlxMysqlAuditLogRepo {}

impl AuditLogRepository for SqlxMysqlAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let id_str = input.id.to_string();
            let user_id_str = input.user_id.map(|u| u.to_string());
            sqlx::query!(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                id_str,
                user_id_str,
                input.event_type,
                input.metadata,
                input.ip_address,
                input.created_at,
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
                 WHERE (? IS NULL OR user_id = ?) \
                   AND (? IS NULL OR event_type = ?) \
                 ORDER BY created_at DESC \
                 LIMIT ? OFFSET ?",
                user_id_str,
                user_id_str,
                event_type,
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
                    id: r.id.parse().unwrap_or_default(),
                    user_id: r.user_id.and_then(|s| s.parse().ok()),
                    event_type: r.event_type,
                    metadata: r.metadata,
                    ip_address: r.ip_address,
                    created_at: r.created_at,
                })
                .collect())
        })
    }
}
