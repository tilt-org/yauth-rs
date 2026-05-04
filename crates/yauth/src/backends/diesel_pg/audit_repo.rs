use diesel::ExpressionMethods;
use diesel::QueryDsl;
use diesel::SelectableHelper;
use diesel_async_crate::RunQueryDsl;

use super::models::*;
use super::schema::*;
use crate::backends::diesel_common::{diesel_err, get_conn};
use crate::domain;
use crate::repo::{AuditLogFilter, AuditLogRepository, RepoFuture, sealed};
use crate::state::DbPool;

pub(crate) struct DieselAuditLogRepo {
    pool: DbPool,
}

impl DieselAuditLogRepo {
    pub(crate) fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl sealed::Sealed for DieselAuditLogRepo {}

impl AuditLogRepository for DieselAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = get_conn(&self.pool).await?;
            let diesel_input = DieselNewAuditLog::from_domain(input);
            diesel::insert_into(yauth_audit_log::table)
                .values(&diesel_input)
                .execute(&mut conn)
                .await
                .map_err(diesel_err)?;
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
            let mut conn = get_conn(&self.pool).await?;
            let mut query = yauth_audit_log::table.into_boxed();
            if let Some(uid) = filter.user_id {
                query = query.filter(yauth_audit_log::user_id.eq(uid));
            }
            if let Some(t) = filter.event_type {
                query = query.filter(yauth_audit_log::event_type.eq(t));
            }
            let rows: Vec<DieselAuditLog> = query
                .order(yauth_audit_log::created_at.desc())
                .limit(limit)
                .offset(offset)
                .select(DieselAuditLog::as_select())
                .load(&mut conn)
                .await
                .map_err(diesel_err)?;
            Ok(rows.into_iter().map(DieselAuditLog::into_domain).collect())
        })
    }
}
