//! Integration tests for the diesel-mysql organizations backend (issue #87).
//!
//! Mirrors `tests/organizations_diesel_pg.rs` so the diesel-mysql impl
//! satisfies the same contract. Requires a MySQL 8.0+ server reachable via
//! `MYSQL_DATABASE_URL`. If the env var is unset or the server is
//! unreachable, every test self-skips — mirroring the pattern in
//! `diesel_mysql_integration.rs` so unattended CI on machines without MySQL
//! still passes.
//!
//! Uses the same shared-runtime + `#[test]` + `block_on` pattern as
//! `tests/repo_conformance.rs` and `tests/organizations_seaorm_mysql.rs` so
//! the OnceCell-initialised diesel-async connection pool lives on a single
//! runtime and survives across every test in this binary. Spawning a fresh
//! `#[tokio::test]` runtime per test races the pool shutdown and surfaces
//! as "A Tokio 1.x context was found, but it is being shutdown".
//!
//! ```text
//! MYSQL_DATABASE_URL=mysql://yauth:yauth@127.0.0.1:3307/yauth_test \
//!   cargo test --features "diesel-mysql-backend,organizations,email-password" \
//!   --test organizations_diesel_mysql
//! ```

#![cfg(all(
    feature = "diesel-mysql-backend",
    feature = "organizations",
    feature = "email-password"
))]

use chrono::Utc;
use std::sync::OnceLock;
use tokio::sync::OnceCell;
use uuid::Uuid;
use yauth::backends::diesel_mysql::{DieselMysqlBackend, MysqlPool};
use yauth::repo::{DatabaseBackend, RepoError, Repositories};
use yauth_entity::{
    MembershipStatus, NewInvitation, NewMembership, NewOrganization, NewUser, UpdateOrganization,
};

mod helpers;

// One multi-thread Tokio runtime for the whole binary. Every test does
// `runtime().block_on(...)`, so the diesel-async pool initialised in the
// first test stays alive on the same runtime for the rest.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("create shared test runtime")
    })
}

/// Shared pool — built once per test binary. We don't drop tables between
/// tests; each test uses unique slugs/tokens (via `unique_suffix`) so rows
/// from different tests never collide.
static SHARED_REPOS: OnceCell<Option<Repositories>> = OnceCell::const_new();

fn mysql_url() -> Option<String> {
    std::env::var("MYSQL_DATABASE_URL").ok()
}

async fn try_build_pool(url: &str) -> Option<MysqlPool> {
    let config = diesel_async_crate::pooled_connection::AsyncDieselConnectionManager::<
        diesel_async_crate::AsyncMysqlConnection,
    >::new(url);
    let pool = match diesel_async_crate::pooled_connection::deadpool::Pool::builder(config)
        .max_size(8)
        .build()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("MySQL pool creation failed: {e}, skipping");
            return None;
        }
    };
    // Probe connectivity once — we want a clean skip, not a panic, when the
    // server isn't running.
    match pool.get().await {
        Ok(_) => Some(pool),
        Err(e) => {
            eprintln!("MySQL not reachable at {url}: {e}, skipping");
            None
        }
    }
}

async fn shared_repos() -> Option<&'static Repositories> {
    SHARED_REPOS
        .get_or_init(|| async {
            let url = mysql_url()?;
            let pool = try_build_pool(&url).await?;
            helpers::schema::setup_mysql_schema_diesel(&pool).await;
            Some(DieselMysqlBackend::from_pool(pool).repositories())
        })
        .await
        .as_ref()
}

/// Skip the test if no MySQL is available. Mirrors the diesel-pg test's
/// `require_db!()` semantics — keep CI green on bare machines.
macro_rules! require_repos {
    () => {
        match shared_repos().await {
            Some(r) => r,
            None => {
                eprintln!("No MySQL available — skipping diesel-mysql orgs test");
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
        suspended_at: None,
        suspended_reason: None,
        activates_at: None,
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

#[test]
fn diesel_mysql_org_create_find_update_delete_round_trip() {
    runtime().block_on(async {
        let repos = require_repos!();

        let org_input = new_org("acme");
        let original_slug = org_input.slug.clone();
        let created = repos.organizations.create(org_input).await.unwrap();
        assert_eq!(created.slug, original_slug);

        // Lookup by id
        let by_id = repos.organizations.find_by_id(created.id).await.unwrap();
        assert_eq!(by_id.unwrap().id, created.id);

        // Lookup by slug, case-insensitive
        let by_slug = repos
            .organizations
            .find_by_slug(&original_slug.to_uppercase())
            .await
            .unwrap();
        assert_eq!(by_slug.unwrap().id, created.id);

        // Update display name
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

        // Delete
        repos.organizations.delete(created.id).await.unwrap();
        assert!(
            repos
                .organizations
                .find_by_id(created.id)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn diesel_mysql_org_slug_uniqueness_is_case_insensitive() {
    runtime().block_on(async {
        let repos = require_repos!();

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

        // Case-insensitive lookup must find the existing row regardless of the
        // table collation (MySQL's default ci collations would also match, but
        // we want `utf8mb4_bin` to work too — see organization_repo.rs).
        let by_upper = repos.organizations.find_by_slug(&upper).await.unwrap();
        assert!(
            by_upper.is_some(),
            "case-insensitive slug lookup should find existing org"
        );

        // Case-folded duplicate rejected (PR #98 H-1: generated `slug_lower`
        // column with UNIQUE KEY enforces case-insensitive uniqueness).
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

        // Duplicate exact slug conflicts at the DB UNIQUE.
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
    });
}

#[test]
fn diesel_mysql_membership_uniqueness_and_listing() {
    runtime().block_on(async {
        let repos = require_repos!();

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

        // Duplicate (org, user) rejected via preflight check.
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

        // List by org and by user.
        let by_org = repos.memberships.list_by_org(org.id).await.unwrap();
        assert_eq!(by_org.len(), 1);
        assert_eq!(by_org[0].id, m.id);

        let by_user = repos.memberships.list_by_user(user.id).await.unwrap();
        assert!(by_user.iter().any(|x| x.id == m.id));

        // find_by_org_user returns the same row.
        let found = repos
            .memberships
            .find_by_org_user(org.id, user.id)
            .await
            .unwrap();
        assert_eq!(found.unwrap().id, m.id);
    });
}

#[test]
fn diesel_mysql_org_list_for_user_returns_only_joined_orgs() {
    runtime().block_on(async {
        let repos = require_repos!();

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
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, org_a.id);
    });
}

#[test]
fn diesel_mysql_org_delete_cascades_to_memberships_and_invitations() {
    runtime().block_on(async {
        let repos = require_repos!();

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

        // Cascade delete via FK ON DELETE CASCADE.
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
    });
}

#[test]
fn diesel_mysql_invitation_token_lookup_filters_expired_and_accepted() {
    runtime().block_on(async {
        let repos = require_repos!();

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

        // Live token resolves.
        assert!(
            repos
                .invitations
                .find_by_token_hash(&live_token)
                .await
                .unwrap()
                .is_some()
        );

        // Expired token does not resolve.
        assert!(
            repos
                .invitations
                .find_by_token_hash(&expired_token)
                .await
                .unwrap()
                .is_none()
        );

        // After acceptance, live token no longer resolves.
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
    });
}

#[test]
fn diesel_mysql_membership_does_not_leak_across_orgs() {
    runtime().block_on(async {
        let repos = require_repos!();

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
    });
}

#[test]
fn diesel_mysql_org_delete_missing_returns_not_found() {
    runtime().block_on(async {
        let repos = require_repos!();

        let missing = repos.organizations.delete(Uuid::now_v7()).await;
        assert!(matches!(missing, Err(RepoError::NotFound)));
    });
}

#[test]
fn diesel_mysql_org_list_with_search_and_pagination() {
    runtime().block_on(async {
        let repos = require_repos!();

        let needle = unique_suffix();
        // Insert 3 orgs all sharing a unique substring.
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
    });
}
