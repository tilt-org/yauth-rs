use sea_orm::prelude::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};

use super::entities::audit_log;
use super::sea_err;
use crate::domain;
use crate::repo::{AuditLogFilter, AuditLogRepository, RepoFuture, sealed};

pub(crate) struct SeaOrmAuditLogRepo {
    db: DatabaseConnection,
}

impl SeaOrmAuditLogRepo {
    pub(crate) fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for SeaOrmAuditLogRepo {}

impl AuditLogRepository for SeaOrmAuditLogRepo {
    fn create(&self, input: domain::NewAuditLog) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let model = audit_log::ActiveModel {
                id: Set(input.id),
                user_id: Set(input.user_id),
                event_type: Set(input.event_type),
                metadata: Set(input.metadata),
                ip_address: Set(input.ip_address),
                created_at: Set(super::to_tz(input.created_at)),
            };
            model.insert(&self.db).await.map_err(sea_err)?;
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
            let mut q = audit_log::Entity::find();
            if let Some(uid) = filter.user_id {
                q = q.filter(audit_log::Column::UserId.eq(uid));
            }
            if let Some(t) = filter.event_type {
                q = q.filter(audit_log::Column::EventType.eq(t));
            }
            let rows = q
                .order_by_desc(audit_log::Column::CreatedAt)
                .limit(limit as u64)
                .offset(offset as u64)
                .all(&self.db)
                .await
                .map_err(sea_err)?;
            Ok(rows
                .into_iter()
                .map(|m| domain::AuditLog {
                    id: m.id,
                    user_id: m.user_id,
                    event_type: m.event_type,
                    metadata: m.metadata,
                    ip_address: m.ip_address,
                    created_at: m.created_at.naive_utc(),
                })
                .collect())
        })
    }
}
