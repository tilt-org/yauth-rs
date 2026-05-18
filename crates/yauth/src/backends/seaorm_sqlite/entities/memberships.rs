//! SeaORM entity for `yauth_memberships` (SQLite dialect).
//!
//! `organization_id` / `user_id` are nullable in the migration to match the
//! cross-dialect schema generator's cascade-friendly form. Domain types treat
//! them as required -- a NULL surfaces as data corruption.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_memberships")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub organization_id: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub user_id: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub role: String,
    #[sea_orm(column_type = "Text")]
    pub status: String,
    pub invited_at: Option<DateTimeWithTimeZone>,
    pub joined_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organizations::Entity",
        from = "Column::OrganizationId",
        to = "super::organizations::Column::Id",
        on_delete = "Cascade"
    )]
    Organization,
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::organizations::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organization.def()
    }
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> Result<crate::domain::Membership, crate::repo::RepoError> {
        let organization_id = self.organization_id.ok_or_else(|| {
            crate::repo::RepoError::Internal(
                "membership row has NULL organization_id (data corruption)".into(),
            )
        })?;
        let user_id = self.user_id.ok_or_else(|| {
            crate::repo::RepoError::Internal(
                "membership row has NULL user_id (data corruption)".into(),
            )
        })?;
        let status = crate::domain::MembershipStatus::parse(&self.status).ok_or_else(|| {
            crate::repo::RepoError::Internal(
                format!("unknown membership status: {:?}", self.status).into(),
            )
        })?;
        Ok(crate::domain::Membership {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            organization_id: crate::backends::seaorm_common::str_to_uuid(&organization_id),
            user_id: crate::backends::seaorm_common::str_to_uuid(&user_id),
            role: self.role,
            status,
            invited_at: self.invited_at.map(|d| d.naive_utc()),
            joined_at: self.joined_at.map(|d| d.naive_utc()),
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        })
    }
}
