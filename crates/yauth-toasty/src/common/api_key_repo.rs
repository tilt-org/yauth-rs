use toasty::Db;
use uuid::Uuid;

use crate::entities::YauthApiKey;
use crate::helpers::{
    chrono_to_jiff, jiff_to_chrono, opt_chrono_to_jiff, opt_jiff_to_chrono, toasty_err,
};
use yauth::repo::{ApiKeyRepository, RepoFuture, sealed};
use yauth_entity as domain;

pub(crate) struct ToastyApiKeyRepo {
    db: Db,
}

impl ToastyApiKeyRepo {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

impl sealed::Sealed for ToastyApiKeyRepo {}

impl ApiKeyRepository for ToastyApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthApiKey::filter_by_key_prefix(&prefix)
                .get(&mut db)
                .await
            {
                Ok(row) => {
                    if let Some(ref exp) = row.expires_at
                        && *exp < jiff::Timestamp::now()
                    {
                        return Ok(None);
                    }
                    Ok(Some(api_key_to_domain(row)))
                }
                Err(_) => Ok(None),
            }
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            match YauthApiKey::get_by_id(&mut db, &id).await {
                Ok(row) if row.user_id == user_id => Ok(Some(api_key_to_domain(row))),
                _ => Ok(None),
            }
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let mut db = self.db.clone();
            let rows: Vec<YauthApiKey> = YauthApiKey::filter_by_user_id(user_id)
                .exec(&mut db)
                .await
                .map_err(toasty_err)?;
            Ok(rows.into_iter().map(api_key_to_domain).collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            // yauth #91: input.user_id is now Option (None = org-scoped).
            // Toasty's YauthApiKey still has Uuid (no Option); for now
            // toasty rejects org-scoped writes by unwrapping. SQL backends
            // own the org-scoped path until toasty migrates.
            let toasty_user_id = input.user_id.expect(
                "toasty backend does not yet support org-scoped api keys (yauth #91 follow-up)",
            );
            toasty::create!(YauthApiKey {
                id: input.id,
                user_id: toasty_user_id,
                key_prefix: input.key_prefix,
                key_hash: input.key_hash,
                name: input.name,
                scopes: input.scopes,
                last_used_at: None::<jiff::Timestamp>,
                expires_at: opt_chrono_to_jiff(input.expires_at),
                created_at: chrono_to_jiff(input.created_at),
            })
            .exec(&mut db)
            .await
            .map_err(toasty_err)?;
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(row) = YauthApiKey::get_by_id(&mut db, &id).await {
                let _ = row.delete().exec(&mut db).await;
            }
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut db = self.db.clone();
            if let Ok(mut row) = YauthApiKey::get_by_id(&mut db, &id).await {
                row.update()
                    .last_used_at(Some(jiff::Timestamp::now()))
                    .exec(&mut db)
                    .await
                    .map_err(toasty_err)?;
            }
            Ok(())
        })
    }
}

fn api_key_to_domain(m: YauthApiKey) -> domain::ApiKey {
    let user_id = m.user_id;
    domain::ApiKey {
        id: m.id,
        // yauth #91: user_id is now `Option<Uuid>` (None for org-scoped keys).
        // Toasty doesn't yet carry the new columns, so all keys round-trip
        // as user-scoped; org-scoped is a follow-up that adds the columns.
        user_id: Some(user_id),
        // yauth #91 — org-scoped API keys columns not yet on toasty.
        organization_id: None,
        key_prefix: m.key_prefix,
        key_hash: m.key_hash,
        name: m.name,
        scopes: m.scopes,
        role: None,
        last_used_at: opt_jiff_to_chrono(m.last_used_at),
        expires_at: opt_jiff_to_chrono(m.expires_at),
        created_at: jiff_to_chrono(m.created_at),
        // yauth #91: required column added in #91; toasty backfills to the
        // user_id field until the column lands.
        created_by_user_id: user_id,
    }
}
