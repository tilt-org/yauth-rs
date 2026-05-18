use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use crate::domain;
use crate::repo::{ApiKeyRepository, RepoError, RepoFuture, sealed};

pub(crate) struct InMemoryApiKeyRepo {
    keys: Arc<RwLock<HashMap<Uuid, domain::ApiKey>>>,
}

impl InMemoryApiKeyRepo {
    pub(crate) fn new(keys: Arc<RwLock<HashMap<Uuid, domain::ApiKey>>>) -> Self {
        Self { keys }
    }
}

impl sealed::Sealed for InMemoryApiKeyRepo {}

impl ApiKeyRepository for InMemoryApiKeyRepo {
    fn find_by_prefix(&self, prefix: &str) -> RepoFuture<'_, Option<domain::ApiKey>> {
        let prefix = prefix.to_string();
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let map = self.keys.read().unwrap();
            // Expiration on read: return None if expired
            Ok(map
                .values()
                .find(|k| k.key_prefix == prefix && k.expires_at.is_none_or(|e| e > now))
                .cloned())
        })
    }

    fn find_by_id_and_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let map = self.keys.read().unwrap();
            Ok(map.get(&id).filter(|k| k.user_id == Some(user_id)).cloned())
        })
    }

    fn list_by_user_id(&self, user_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let map = self.keys.read().unwrap();
            Ok(map
                .values()
                .filter(|k| k.user_id == Some(user_id))
                .cloned()
                .collect())
        })
    }

    fn create(&self, input: domain::NewApiKey) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            // Enforce exactly-one-owner invariant (issue #91).
            match (input.user_id, input.organization_id) {
                (Some(_), Some(_)) => {
                    return Err(RepoError::Conflict(
                        "api key cannot have both user_id and organization_id".to_string(),
                    ));
                }
                (None, None) => {
                    return Err(RepoError::Conflict(
                        "api key must have either user_id or organization_id".to_string(),
                    ));
                }
                _ => {}
            }

            let mut map = self.keys.write().unwrap();
            // Enforce name uniqueness per owner (user or org).
            let dup = map.values().any(|k| {
                k.name == input.name
                    && match (input.user_id, input.organization_id) {
                        (Some(u), _) => k.user_id == Some(u),
                        (_, Some(o)) => k.organization_id == Some(o),
                        _ => false,
                    }
            });
            if dup {
                return Err(RepoError::Conflict(
                    "duplicate API key name for this owner".to_string(),
                ));
            }

            let key = domain::ApiKey {
                id: input.id,
                user_id: input.user_id,
                organization_id: input.organization_id,
                key_prefix: input.key_prefix,
                key_hash: input.key_hash,
                name: input.name,
                scopes: input.scopes,
                role: input.role,
                last_used_at: None,
                expires_at: input.expires_at,
                created_at: input.created_at,
                created_by_user_id: input.created_by_user_id,
            };
            map.insert(key.id, key);
            Ok(())
        })
    }

    fn delete(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.keys.write().unwrap();
            map.remove(&id);
            Ok(())
        })
    }

    fn update_last_used(&self, id: Uuid) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let now = Utc::now().naive_utc();
            let mut map = self.keys.write().unwrap();
            if let Some(key) = map.get_mut(&id) {
                key.last_used_at = Some(now);
            }
            Ok(())
        })
    }

    // ── Org-scoped operations (issue #91) ───────────────────────────

    fn find_by_id_and_org(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> RepoFuture<'_, Option<domain::ApiKey>> {
        Box::pin(async move {
            let map = self.keys.read().unwrap();
            Ok(map
                .get(&id)
                .filter(|k| k.organization_id == Some(organization_id))
                .cloned())
        })
    }

    fn list_by_org_id(&self, organization_id: Uuid) -> RepoFuture<'_, Vec<domain::ApiKey>> {
        Box::pin(async move {
            let map = self.keys.read().unwrap();
            let mut out: Vec<_> = map
                .values()
                .filter(|k| k.organization_id == Some(organization_id))
                .cloned()
                .collect();
            out.sort_by_key(|k| std::cmp::Reverse(k.created_at));
            Ok(out)
        })
    }

    fn set_expires_at(&self, id: Uuid, expires_at: chrono::NaiveDateTime) -> RepoFuture<'_, ()> {
        Box::pin(async move {
            let mut map = self.keys.write().unwrap();
            if let Some(key) = map.get_mut(&id) {
                key.expires_at = Some(expires_at);
            }
            Ok(())
        })
    }
}
