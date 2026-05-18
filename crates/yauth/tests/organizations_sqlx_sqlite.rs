//! Integration tests for the sqlx-sqlite organizations backend (issue #87).
//!
//! Mirrors `tests/organizations_sqlx_pg.rs` so the sqlx-sqlite impl
//! satisfies the same contract. Uses an in-memory SQLite database — no
//! external services required, never skipped.
//!
//! ```text
//! cargo test --features "sqlx-sqlite-backend,organizations,email-password" \
//!   --test organizations_sqlx_sqlite
//! ```

#![cfg(all(
    feature = "sqlx-sqlite-backend",
    feature = "organizations",
    feature = "email-password"
))]

use chrono::Utc;
use sqlx::SqlitePool;
use tokio::sync::OnceCell;
use uuid::Uuid;
use yauth::backends::sqlx_sqlite::SqlxSqliteBackend;
use yauth::repo::{DatabaseBackend, RepoError, Repositories};
use yauth_entity::{
    MembershipStatus, NewInvitation, NewMembership, NewOrganization, NewUser, UpdateOrganization,
};

mod helpers;

/// Holds the sqlx SQLite pool. In-memory by default; honours
/// `SQLX_SQLITE_DATABASE_URL` for parity with the conformance suite.
pub struct SqlxSqliteTestDb {
    pub pool: SqlitePool,
}

static SHARED_DB: OnceCell<Option<SqlxSqliteTestDb>> = OnceCell::const_new();

impl SqlxSqliteTestDb {
    pub async fn shared() -> Option<&'static SqlxSqliteTestDb> {
        SHARED_DB
            .get_or_init(|| async { Self::try_new_shared().await })
            .await
            .as_ref()
    }

    async fn try_new_shared() -> Option<Self> {
        let url = std::env::var("SQLX_SQLITE_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite::memory:".to_string());
        match SqlitePool::connect(&url).await {
            Ok(pool) => {
                // `setup_sqlite_schema_sqlx` runs `PRAGMA foreign_keys=ON`
                // before applying the DDL — required for cascade-delete
                // tests to pass.
                helpers::schema::setup_sqlite_schema_sqlx(&pool).await;
                Some(Self { pool })
            }
            Err(e) => {
                eprintln!("sqlx-sqlite pool creation failed: {e}");
                None
            }
        }
    }
}

/// Always available (in-memory SQLite) — the skip macro is kept for parity
/// with the other backend test files. If pool init ever fails the test is
/// reported as skipped rather than failing.
macro_rules! require_db {
    () => {
        match SqlxSqliteTestDb::shared().await {
            Some(db) => db,
            None => {
                eprintln!("No database available — skipping sqlx-sqlite orgs test");
                return;
            }
        }
    };
}

fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

fn unique_suffix() -> String {
    Uuid::now_v7().simple().to_string()
}

fn new_user(email_prefix: &str) -> NewUser {
    let n = now();
    NewUser {
        id: Uuid::now_v7(),
        email: format!("{email_prefix}-{}@example.com", unique_suffix()),
        display_name: None,
        email_verified: true,
        role: "user".to_string(),
        banned: false,
        banned_reason: None,
        banned_until: None,
        created_at: n,
        updated_at: n,
    }
}

fn new_org(slug_prefix: &str) -> NewOrganization {
    let n = now();
    let slug = format!("{slug_prefix}-{}", unique_suffix());
    NewOrganization {
        id: Uuid::now_v7(),
        name: slug.clone(),
        slug,
        display_name: None,
        avatar_url: None,
        metadata: None,
        created_at: n,
        updated_at: n,
    }
}

async fn make_repos(db: &SqlxSqliteTestDb) -> Repositories {
    SqlxSqliteBackend::from_pool(db.pool.clone()).repositories()
}

#[tokio::test]
async fn sqlx_sqlite_org_create_find_update_delete_round_trip() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let org_input = new_org("acme");
    let original_slug = org_input.slug.clone();
    let created = repos.organizations.create(org_input).await.unwrap();
    assert_eq!(created.slug, original_slug);

    let by_id = repos.organizations.find_by_id(created.id).await.unwrap();
    assert_eq!(by_id.unwrap().id, created.id);

    let by_slug = repos
        .organizations
        .find_by_slug(&original_slug.to_uppercase())
        .await
        .unwrap();
    assert_eq!(by_slug.unwrap().id, created.id);

    let updated = repos
        .organizations
        .update(
            created.id,
            UpdateOrganization {
                display_name: Some(Some("Acme Corp".to_string())),
                updated_at: Some(now()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.display_name.as_deref(), Some("Acme Corp"));

    repos.organizations.delete(created.id).await.unwrap();
    assert!(
        repos
            .organizations
            .find_by_id(created.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sqlx_sqlite_org_slug_uniqueness_is_case_insensitive() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let suffix = unique_suffix();
    let n = now();
    let lower = format!("acme-{suffix}");
    let upper = lower.to_uppercase();

    repos
        .organizations
        .create(NewOrganization {
            id: Uuid::now_v7(),
            name: lower.clone(),
            slug: lower.clone(),
            display_name: None,
            avatar_url: None,
            metadata: None,
            created_at: n,
            updated_at: n,
        })
        .await
        .unwrap();

    // Case-insensitive lookup must find the existing row.
    let by_upper = repos.organizations.find_by_slug(&upper).await.unwrap();
    assert!(
        by_upper.is_some(),
        "case-insensitive slug lookup should find existing org"
    );

    // Case-folded duplicate must conflict at the DB level (PR #98 security
    // review H-1). The migration now declares a functional unique index on
    // `LOWER(slug)`, which SQLite enforces natively.
    let dup_upper = repos
        .organizations
        .create(NewOrganization {
            id: Uuid::now_v7(),
            name: upper.clone(),
            slug: upper,
            display_name: None,
            avatar_url: None,
            metadata: None,
            created_at: n,
            updated_at: n,
        })
        .await;
    assert!(
        matches!(dup_upper, Err(RepoError::Conflict(_))),
        "case-folded duplicate slug must be rejected; got {dup_upper:?}"
    );

    // Exact-case duplicate must also conflict.
    let dup = repos
        .organizations
        .create(NewOrganization {
            id: Uuid::now_v7(),
            name: lower.clone(),
            slug: lower,
            display_name: None,
            avatar_url: None,
            metadata: None,
            created_at: n,
            updated_at: n,
        })
        .await;
    assert!(matches!(dup, Err(RepoError::Conflict(_))));
}

#[tokio::test]
async fn sqlx_sqlite_org_slug_uniqueness_uppercase_variant_conflicts() {
    // SQLite-specific: the migration's UNIQUE(slug) is BINARY-collated so
    // it does NOT catch `"acme"` vs `"Acme"` on its own. The repo's
    // preflight `LOWER(slug) = LOWER(?)` SELECT is what enforces parity
    // with diesel-pg's ILIKE.
    let db = require_db!();
    let repos = make_repos(db).await;

    let suffix = unique_suffix();
    let n = now();
    let lower = format!("acme-case-{suffix}");
    let upper = lower.to_uppercase();

    repos
        .organizations
        .create(NewOrganization {
            id: Uuid::now_v7(),
            name: lower.clone(),
            slug: lower,
            display_name: None,
            avatar_url: None,
            metadata: None,
            created_at: n,
            updated_at: n,
        })
        .await
        .unwrap();

    let dup_upper = repos
        .organizations
        .create(NewOrganization {
            id: Uuid::now_v7(),
            name: upper.clone(),
            slug: upper,
            display_name: None,
            avatar_url: None,
            metadata: None,
            created_at: n,
            updated_at: n,
        })
        .await;
    assert!(matches!(dup_upper, Err(RepoError::Conflict(_))));
}

#[tokio::test]
async fn sqlx_sqlite_membership_uniqueness_and_listing() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let user = repos.users.create(new_user("a")).await.unwrap();
    let org = repos.organizations.create(new_org("uniq")).await.unwrap();

    let n = now();
    let m = repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org.id,
            user_id: user.id,
            role: "admin".to_string(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(n),
            created_at: n,
            updated_at: n,
        })
        .await
        .unwrap();

    let dup = repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org.id,
            user_id: user.id,
            role: "member".to_string(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(n),
            created_at: n,
            updated_at: n,
        })
        .await;
    assert!(matches!(dup, Err(RepoError::Conflict(_))));

    let by_org = repos.memberships.list_by_org(org.id).await.unwrap();
    assert_eq!(by_org.len(), 1);
    assert_eq!(by_org[0].id, m.id);

    let by_user = repos.memberships.list_by_user(user.id).await.unwrap();
    assert!(by_user.iter().any(|x| x.id == m.id));

    let found = repos
        .memberships
        .find_by_org_user(org.id, user.id)
        .await
        .unwrap();
    assert_eq!(found.unwrap().id, m.id);
}

#[tokio::test]
async fn sqlx_sqlite_org_list_for_user_returns_only_joined_orgs() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let user = repos.users.create(new_user("listfu")).await.unwrap();
    let org_a = repos
        .organizations
        .create(new_org("listfua"))
        .await
        .unwrap();
    let _org_b = repos
        .organizations
        .create(new_org("listfub"))
        .await
        .unwrap();
    let n = now();

    repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org_a.id,
            user_id: user.id,
            role: "admin".to_string(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(n),
            created_at: n,
            updated_at: n,
        })
        .await
        .unwrap();

    let mine = repos.organizations.list_for_user(user.id).await.unwrap();
    assert!(mine.iter().any(|o| o.id == org_a.id));
    assert!(mine.iter().all(|o| o.id != _org_b.id));
}

#[tokio::test]
async fn sqlx_sqlite_org_delete_cascades_to_memberships_and_invitations() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let user = repos.users.create(new_user("cascade")).await.unwrap();
    let org = repos
        .organizations
        .create(new_org("cascade"))
        .await
        .unwrap();
    let n = now();

    repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org.id,
            user_id: user.id,
            role: "admin".to_string(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(n),
            created_at: n,
            updated_at: n,
        })
        .await
        .unwrap();

    let invite_token = format!("cascade-{}", unique_suffix());
    repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: format!("invite-{}@example.com", unique_suffix()),
            role: "member".to_string(),
            token_hash: invite_token,
            invited_by_user_id: user.id,
            expires_at: n + chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();

    // Cascade delete via FK ON DELETE CASCADE — requires PRAGMA
    // foreign_keys = ON on this connection, set by setup_sqlite_schema_sqlx.
    repos.organizations.delete(org.id).await.unwrap();

    assert!(
        repos
            .memberships
            .list_by_org(org.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos
            .invitations
            .list_pending_for_org(org.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn sqlx_sqlite_invitation_token_lookup_filters_expired_and_accepted() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let user = repos.users.create(new_user("invitee")).await.unwrap();
    let org = repos.organizations.create(new_org("invite")).await.unwrap();
    let n = now();

    let live_token = format!("live-{}", unique_suffix());
    let live = repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: format!("live-{}@example.com", unique_suffix()),
            role: "member".to_string(),
            token_hash: live_token.clone(),
            invited_by_user_id: user.id,
            expires_at: n + chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();

    let expired_token = format!("expired-{}", unique_suffix());
    let _expired = repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: format!("expired-{}@example.com", unique_suffix()),
            role: "member".to_string(),
            token_hash: expired_token.clone(),
            invited_by_user_id: user.id,
            expires_at: n - chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();

    assert!(
        repos
            .invitations
            .find_by_token_hash(&live_token)
            .await
            .unwrap()
            .is_some()
    );

    assert!(
        repos
            .invitations
            .find_by_token_hash(&expired_token)
            .await
            .unwrap()
            .is_none()
    );

    repos.invitations.mark_accepted(live.id, n).await.unwrap();
    assert!(
        repos
            .invitations
            .find_by_token_hash(&live_token)
            .await
            .unwrap()
            .is_none()
    );

    // Double-accept returns NotFound (single-shot semantics).
    let dbl = repos.invitations.mark_accepted(live.id, n).await;
    assert!(matches!(dbl, Err(RepoError::NotFound)));
}

#[tokio::test]
async fn sqlx_sqlite_membership_does_not_leak_across_orgs() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let alice = repos.users.create(new_user("alice")).await.unwrap();
    let bob = repos.users.create(new_user("bob")).await.unwrap();
    let org_a = repos.organizations.create(new_org("isoa")).await.unwrap();
    let org_b = repos.organizations.create(new_org("isob")).await.unwrap();
    let n = now();

    for (uid, oid) in [(alice.id, org_a.id), (bob.id, org_b.id)] {
        repos
            .memberships
            .create(NewMembership {
                id: Uuid::now_v7(),
                organization_id: oid,
                user_id: uid,
                role: "admin".to_string(),
                status: MembershipStatus::Active,
                invited_at: None,
                joined_at: Some(n),
                created_at: n,
                updated_at: n,
            })
            .await
            .unwrap();
    }

    let a_members = repos.memberships.list_by_org(org_a.id).await.unwrap();
    assert_eq!(a_members.len(), 1);
    assert_eq!(a_members[0].user_id, alice.id);

    let b_members = repos.memberships.list_by_org(org_b.id).await.unwrap();
    assert_eq!(b_members.len(), 1);
    assert_eq!(b_members[0].user_id, bob.id);

    let alice_orgs = repos.organizations.list_for_user(alice.id).await.unwrap();
    assert!(alice_orgs.iter().any(|o| o.id == org_a.id));
    assert!(!alice_orgs.iter().any(|o| o.id == org_b.id));
}

#[tokio::test]
async fn sqlx_sqlite_org_delete_missing_returns_not_found() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let missing = repos.organizations.delete(Uuid::now_v7()).await;
    assert!(matches!(missing, Err(RepoError::NotFound)));
}

#[tokio::test]
async fn sqlx_sqlite_org_list_with_search_and_pagination() {
    let db = require_db!();
    let repos = make_repos(db).await;

    let needle = unique_suffix();
    for i in 0..3 {
        let n = now();
        let slug = format!("search-{needle}-{i}");
        repos
            .organizations
            .create(NewOrganization {
                id: Uuid::now_v7(),
                name: slug.clone(),
                slug,
                display_name: None,
                avatar_url: None,
                metadata: None,
                created_at: n,
                updated_at: n,
            })
            .await
            .unwrap();
    }

    let (page, total) = repos.organizations.list(Some(&needle), 2, 0).await.unwrap();
    assert_eq!(total, 3);
    assert_eq!(page.len(), 2);

    let (page2, _) = repos.organizations.list(Some(&needle), 2, 2).await.unwrap();
    assert_eq!(page2.len(), 1);
}
