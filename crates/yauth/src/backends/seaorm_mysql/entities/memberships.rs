//! SeaORM entity for `yauth_memberships` (MySQL dialect).
//!
//! `organization_id` and `user_id` are stored as nullable `CHAR(36)` because the
//! cross-dialect plugin schema generator emits nullable FKs alongside
//! `ON DELETE CASCADE`. That is a quirk of the cascade declaration, not a
//! semantic — domain types treat both as non-null and a `NULL` row signals
//! data corruption (see `membership_repo::into_domain`).

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_memberships")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
    pub id: String,
    #[sea_orm(column_type = "Char(Some(36))", nullable)]
    pub organization_id: Option<String>,
    #[sea_orm(column_type = "Char(Some(36))", nullable)]
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
