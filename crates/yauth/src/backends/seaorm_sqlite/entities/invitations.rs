//! SeaORM entity for `yauth_invitations` (SQLite dialect).
//!
//! Cascade-friendly FK columns are nullable in the migration; we treat NULL
//! as data corruption at the domain boundary.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_invitations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub organization_id: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub email: String,
    #[sea_orm(column_type = "Text")]
    pub role: String,
    #[sea_orm(column_type = "Text", unique)]
    pub token_hash: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub invited_by_user_id: Option<String>,
    pub expires_at: DateTimeWithTimeZone,
    pub accepted_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
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
        from = "Column::InvitedByUserId",
        to = "super::users::Column::Id",
        on_delete = "Cascade"
    )]
    InvitedBy,
}

impl Related<super::organizations::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organization.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> Result<crate::domain::Invitation, crate::repo::RepoError> {
        let organization_id = self.organization_id.ok_or_else(|| {
            crate::repo::RepoError::Internal(
                "invitation row has NULL organization_id (data corruption)".into(),
            )
        })?;
        let invited_by_user_id = self.invited_by_user_id.ok_or_else(|| {
            crate::repo::RepoError::Internal(
                "invitation row has NULL invited_by_user_id (data corruption)".into(),
            )
        })?;
        Ok(crate::domain::Invitation {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            organization_id: crate::backends::seaorm_common::str_to_uuid(&organization_id),
            email: self.email,
            role: self.role,
            token_hash: self.token_hash,
            invited_by_user_id: crate::backends::seaorm_common::str_to_uuid(&invited_by_user_id),
            expires_at: self.expires_at.naive_utc(),
            accepted_at: self.accepted_at.map(|d| d.naive_utc()),
            created_at: self.created_at.naive_utc(),
        })
    }
}
