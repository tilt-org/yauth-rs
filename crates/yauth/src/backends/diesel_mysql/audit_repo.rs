use super::MysqlPool;
use super::models::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{AuditLogFilter, AuditLogRepository, RepoFuture, sealed};
use diesel::prelude::*;
use diesel_async_crate::RunQueryDsl;

pub(crate) struct MysqlAuditLogRepo {
    pool: MysqlPool,
}
impl MysqlAuditLogRepo {
    pub(crate) fn new(pool: MysqlPool) -> Self {
        Self { pool }
    }
}
impl sealed::Sealed for MysqlAuditLogRepo {}

impl AuditLogRepository for MysqlAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let a = MysqlNewAuditLog::from_domain(input);
            diesel::sql_query(
                "INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind::<diesel::sql_types::Text, _>(&a.id)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&a.user_id)
            .bind::<diesel::sql_types::Text, _>(&a.event_type)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&a.metadata)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(&a.ip_address)
            .bind::<diesel::sql_types::Datetime, _>(&a.created_at)
            .execute(&mut *conn).await.map_err(diesel_err)?;
            Ok(())
        })
    }

    fn list(
        &self,
        filter: AuditLogFilter,
        limit: i64,
        offset: i64,
    ) -> RepoFuture<'_, Vec<domain::AuditLog>> {
        use super::schema::yauth_audit_log;
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let mut query = yauth_audit_log::table.into_boxed();
            if let Some(uid) = filter.user_id {
                query = query.filter(
                    yauth_audit_log::user_id.eq(crate::backends::diesel_common::uuid_to_str(uid)),
                );
            }
            if let Some(t) = filter.event_type {
                query = query.filter(yauth_audit_log::event_type.eq(t));
            }
            let rows: Vec<MysqlAuditLog> = query
                .order(yauth_audit_log::created_at.desc())
                .limit(limit)
                .offset(offset)
                .select(MysqlAuditLog::as_select())
                .load(&mut *conn)
                .await
                .map_err(diesel_err)?;
            Ok(rows.into_iter().map(MysqlAuditLog::into_domain).collect())
        })
    }
}
