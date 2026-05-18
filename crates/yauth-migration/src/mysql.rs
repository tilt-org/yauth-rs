//! MySQL DDL generation.
//!
//! Maps abstract column types to MySQL-compatible types:
//! - UUID -> CHAR(36)
//! - VARCHAR -> VARCHAR(255)
//! - VarcharN(n) -> VARCHAR(n)
//! - BOOLEAN -> TINYINT(1)
//! - DateTime -> DATETIME
//! - Json -> JSON
//! - INT -> INT
//! - SMALLINT -> SMALLINT
//! - TEXT -> TEXT

use std::borrow::Cow;

use super::collector::YAuthSchema;
use super::types::*;

/// Map abstract column type to MySQL type string.
pub(crate) fn mysql_type(col_type: &ColumnType) -> Cow<'static, str> {
    match col_type {
        ColumnType::Uuid => Cow::Borrowed("CHAR(36)"),
        ColumnType::Varchar => Cow::Borrowed("VARCHAR(255)"),
        ColumnType::VarcharN(n) => Cow::Owned(format!("VARCHAR({n})")),
        ColumnType::Boolean => Cow::Borrowed("TINYINT(1)"),
        ColumnType::DateTime => Cow::Borrowed("DATETIME"),
        ColumnType::Json => Cow::Borrowed("JSON"),
        ColumnType::Int => Cow::Borrowed("INT"),
        ColumnType::SmallInt => Cow::Borrowed("SMALLINT"),
        ColumnType::Text => Cow::Borrowed("TEXT"),
    }
}

/// Map OnDelete action to MySQL clause.
fn mysql_on_delete(action: &OnDelete) -> &'static str {
    match action {
        OnDelete::Cascade => "ON DELETE CASCADE",
        OnDelete::SetNull => "ON DELETE SET NULL",
        OnDelete::Restrict => "ON DELETE RESTRICT",
        OnDelete::NoAction => "ON DELETE NO ACTION",
    }
}

/// Map a Postgres default expression to its MySQL equivalent.
pub(crate) fn mysql_default(pg_default: &str) -> Option<Cow<'static, str>> {
    match pg_default {
        "gen_random_uuid()" => None,
        "now()" => Some(Cow::Borrowed("CURRENT_TIMESTAMP")),
        other => Some(Cow::Owned(other.to_string())),
    }
}

/// Generate a CREATE TABLE IF NOT EXISTS statement for a single table (MySQL).
///
/// MySQL silently ignores inline `REFERENCES` on columns; foreign key constraints
/// must be declared as separate `FOREIGN KEY (col) REFERENCES table(col)` lines
/// after all column definitions.
fn generate_create_table(table: &TableDef) -> String {
    let mut sql = String::new();
    if let Some(ref desc) = table.description {
        sql.push_str(&format!("-- {desc}\n"));
    }
    sql.push_str(&format!("CREATE TABLE IF NOT EXISTS `{}` (\n", table.name));

    // Build all table body lines first, then join with commas. This keeps
    // trailing-comma handling sane across the four kinds of lines: columns,
    // FK constraints, generated shadow columns, and unique keys.
    let mut lines: Vec<String> = Vec::with_capacity(table.columns.len() + 4);

    for col in &table.columns {
        let mut line = String::new();
        line.push_str("    `");
        line.push_str(&col.name);
        line.push_str("` ");
        line.push_str(&mysql_type(&col.col_type));

        if col.primary_key {
            line.push_str(" PRIMARY KEY");
            if let Some(ref default) = col.default
                && let Some(mapped) = mysql_default(default)
            {
                line.push_str(" DEFAULT ");
                line.push_str(&mapped);
            }
        } else {
            if !col.nullable {
                line.push_str(" NOT NULL");
            }
            // case_insensitive_unique takes precedence — a generated shadow
            // column is emitted below with its own unique key.
            if col.unique && !col.case_insensitive_unique {
                line.push_str(" UNIQUE");
            }
            if let Some(ref default) = col.default
                && let Some(mapped) = mysql_default(default)
            {
                line.push_str(" DEFAULT ");
                line.push_str(&mapped);
            }
        }
        lines.push(line);
    }

    // Generated shadow columns + unique keys for case-insensitive uniqueness.
    // MySQL functional indexes on `LOWER(col)` require 8.0.13+; a STORED
    // generated column with a unique constraint works on MySQL 5.7+ and
    // MariaDB 10.2+.
    for col in table.columns.iter().filter(|c| c.case_insensitive_unique) {
        lines.push(format!(
            "    `{col}_lower` {ty} GENERATED ALWAYS AS (LOWER(`{col}`)) STORED",
            col = col.name,
            ty = mysql_type(&col.col_type),
        ));
        lines.push(format!(
            "    UNIQUE KEY `{table}_{col}_lower_key` (`{col}_lower`)",
            table = table.name,
            col = col.name,
        ));
    }

    // FK constraints (collected last so they appear at the end of the body).
    for col in &table.columns {
        if let Some(ref fk) = col.foreign_key {
            lines.push(format!(
                "    FOREIGN KEY (`{}`) REFERENCES `{}`(`{}`) {}",
                col.name,
                fk.references_table,
                fk.references_column,
                mysql_on_delete(&fk.on_delete)
            ));
        }
    }

    let last = lines.len().saturating_sub(1);
    for (i, line) in lines.iter().enumerate() {
        sql.push_str(line);
        if i < last {
            sql.push(',');
        }
        sql.push('\n');
    }

    sql.push_str(") ENGINE=InnoDB;\n");
    sql
}

/// Generate complete MySQL DDL for the entire schema.
pub fn generate_mysql_ddl(schema: &YAuthSchema) -> String {
    let mut ddl = String::new();
    for (i, table) in schema.tables.iter().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_create_table(table));
    }
    ddl
}

/// Generate DROP TABLE IF EXISTS statement for a single table (MySQL).
pub fn generate_mysql_drop(table: &TableDef) -> String {
    format!("DROP TABLE IF EXISTS `{}`;\n", table.name)
}

/// Generate DROP TABLE statements for a list of tables in reverse order (MySQL).
pub fn generate_mysql_drops(tables: &[TableDef]) -> String {
    let mut ddl = String::new();
    for (i, table) in tables.iter().rev().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_mysql_drop(table));
    }
    ddl
}
