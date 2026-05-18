//! SeaORM entity for `yauth_invitations`.
//!
//! The migration declares `organization_id` and `invited_by_user_id` as
//! nullable FKs so the cross-dialect `ON DELETE CASCADE` works uniformly.
//! Logically both columns are non-null; a `NULL` from the database is treated
//! as data corruption by the repo layer.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_invitations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Uuid")]
    pub id: Uuid,
    #[sea_orm(column_type = "Uuid", nullable)]
    pub organization_id: Option<Uuid>,
    #[sea_orm(column_type = "Text")]
    pub email: String,
    #[sea_orm(column_type = "Text")]
    pub role: String,
    #[sea_orm(column_type = "String(StringLen::N(64))", unique)]
    pub token_hash: String,
    #[sea_orm(column_type = "Uuid", nullable)]
    pub invited_by_user_id: Option<Uuid>,
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
