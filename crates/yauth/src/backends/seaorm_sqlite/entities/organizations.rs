//! SeaORM entity for `yauth_organizations` (SQLite dialect).
//!
//! SQLite stores UUIDs as TEXT and JSON as TEXT (per `generate_sqlite_ddl`).
//! Metadata is stored as a serialized JSON string and parsed at the
//! domain boundary.

use sea_orm::entity::prelude::*;
use sea_orm::prelude::DateTimeWithTimeZone;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "yauth_organizations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub name: String,
    #[sea_orm(column_type = "Text", unique)]
    pub slug: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub display_name: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub avatar_url: Option<String>,
    /// Stored as TEXT (JSON string).
    #[sea_orm(column_type = "Text", nullable)]
    pub metadata: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn into_domain(self) -> crate::domain::Organization {
        crate::domain::Organization {
            id: crate::backends::seaorm_common::str_to_uuid(&self.id),
            name: self.name,
            slug: self.slug,
            display_name: self.display_name,
            avatar_url: self.avatar_url,
            metadata: self
                .metadata
                .map(|s| crate::backends::seaorm_common::str_to_json(&s)),
            created_at: self.created_at.naive_utc(),
            updated_at: self.updated_at.naive_utc(),
        }
    }
}
