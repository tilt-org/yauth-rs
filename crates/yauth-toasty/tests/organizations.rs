//! Integration tests for the organizations primitive on the Toasty backend
//! (issue #87).
//!
//! Mirrors `crates/yauth/tests/organizations.rs` (memory backend) against
//! `ToastySqliteBackend` so we get behavioural parity coverage for the
//! Toasty repo impls. Toasty's single-entity-set means PG/MySQL/SQLite
//! share the same repo code; running the suite on SQLite is sufficient to
//! exercise the entity ↔ domain mapping, and the CI matrix re-runs the
//! same build on the other two drivers.

#![cfg(all(feature = "organizations", feature = "sqlite"))]

use chrono::Utc;
use uuid::Uuid;

use yauth::repo::{DatabaseBackend, RepoError, Repositories};
use yauth_entity::{
    MembershipStatus, NewInvitation, NewMembership, NewOrganization, NewUser, UpdateOrganization,
};
use yauth_toasty::sqlite::ToastySqliteBackend;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

fn new_user(email: &str) -> NewUser {
    let n = now();
    NewUser {
        id: Uuid::now_v7(),
        email: email.to_string(),
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

fn new_org(slug: &str) -> NewOrganization {
    let n = now();
    NewOrganization {
        id: Uuid::now_v7(),
        name: slug.to_string(),
        slug: slug.to_string(),
        display_name: None,
        avatar_url: None,
        metadata: None,
        created_at: n,
        updated_at: n,
    }
}

/// Spin up an isolated in-memory SQLite Toasty backend per test.
///
/// We deliberately do NOT share a backend across tests — each in-memory
/// SQLite Db is its own keyspace, and a fresh one keeps the assertions
/// (e.g. "exactly 1 row in list_by_org") trivial to write.
async fn fresh_backend() -> Repositories {
    let backend = ToastySqliteBackend::new("sqlite::memory:")
        .await
        .expect("create ToastySqliteBackend");
    backend
        .create_tables()
        .await
        .expect("create_tables (push_schema)");
    backend.repositories()
}

// ---------------------------------------------------------------------------
// OrganizationRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn org_create_find_update_delete_round_trip() {
    let repos = fresh_backend().await;

    let created = repos.organizations.create(new_org("acme")).await.unwrap();
    assert_eq!(created.slug, "acme");

    // find_by_id
    let by_id = repos.organizations.find_by_id(created.id).await.unwrap();
    assert_eq!(by_id.unwrap().id, created.id);

    // find_by_slug — case-insensitive
    let by_slug = repos.organizations.find_by_slug("ACME").await.unwrap();
    assert_eq!(by_slug.unwrap().id, created.id);

    // update display_name
    let updated = repos
        .organizations
        .update(
            created.id,
            UpdateOrganization {
                display_name: Some(Some("Acme Corp".to_string())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.display_name.as_deref(), Some("Acme Corp"));

    // delete
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
async fn org_slug_uniqueness_is_case_insensitive() {
    let repos = fresh_backend().await;
    repos.organizations.create(new_org("acme")).await.unwrap();
    let err = repos
        .organizations
        .create(new_org("ACME"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepoError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
}

#[tokio::test]
async fn org_delete_missing_returns_not_found() {
    let repos = fresh_backend().await;
    let err = repos
        .organizations
        .delete(Uuid::now_v7())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepoError::NotFound),
        "expected NotFound, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// MembershipRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn membership_uniqueness_and_listing() {
    let repos = fresh_backend().await;

    let user = repos.users.create(new_user("a@example.com")).await.unwrap();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
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

    // Duplicate (org, user) rejected (preflight check).
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
    assert!(
        matches!(dup, Err(RepoError::Conflict(_))),
        "expected Conflict on duplicate (org,user), got {dup:?}"
    );

    // list_by_org and list_by_user.
    let by_org = repos.memberships.list_by_org(org.id).await.unwrap();
    assert_eq!(by_org.len(), 1);
    assert_eq!(by_org[0].id, m.id);

    let by_user = repos.memberships.list_by_user(user.id).await.unwrap();
    assert_eq!(by_user.len(), 1);

    // find_by_org_user returns the membership.
    let found = repos
        .memberships
        .find_by_org_user(org.id, user.id)
        .await
        .unwrap();
    assert_eq!(found.unwrap().id, m.id);
}

#[tokio::test]
async fn org_list_for_user_returns_only_joined_orgs() {
    let repos = fresh_backend().await;

    let user = repos.users.create(new_user("a@example.com")).await.unwrap();
    let org_a = repos.organizations.create(new_org("a")).await.unwrap();
    let _org_b = repos.organizations.create(new_org("b")).await.unwrap();

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
}

// ---------------------------------------------------------------------------
// Cascade delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn org_delete_cascades_to_memberships_and_invitations() {
    let repos = fresh_backend().await;

    let user = repos.users.create(new_user("a@example.com")).await.unwrap();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
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

    repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: "invite@example.com".to_string(),
            role: "member".to_string(),
            token_hash: "cascade-token".to_string(),
            invited_by_user_id: user.id,
            expires_at: n + chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();

    repos.organizations.delete(org.id).await.unwrap();

    assert!(
        repos
            .memberships
            .list_by_org(org.id)
            .await
            .unwrap()
            .is_empty(),
        "memberships should cascade away"
    );
    assert!(
        repos
            .invitations
            .list_pending_for_org(org.id)
            .await
            .unwrap()
            .is_empty(),
        "invitations should cascade away"
    );
}

// ---------------------------------------------------------------------------
// InvitationRepository
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invitation_token_lookup_filters_expired_and_accepted() {
    let repos = fresh_backend().await;

    let user = repos.users.create(new_user("a@example.com")).await.unwrap();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let n = now();

    let live = repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: "x@example.com".to_string(),
            role: "member".to_string(),
            token_hash: "live-hash".to_string(),
            invited_by_user_id: user.id,
            expires_at: n + chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();

    let _expired = repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: "y@example.com".to_string(),
            role: "member".to_string(),
            token_hash: "expired-hash".to_string(),
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
            .find_by_token_hash("live-hash")
            .await
            .unwrap()
            .is_some()
    );

    // Expired token does not.
    assert!(
        repos
            .invitations
            .find_by_token_hash("expired-hash")
            .await
            .unwrap()
            .is_none()
    );

    // After acceptance, the live token no longer resolves.
    repos.invitations.mark_accepted(live.id, n).await.unwrap();
    assert!(
        repos
            .invitations
            .find_by_token_hash("live-hash")
            .await
            .unwrap()
            .is_none()
    );

    // Double-accept returns NotFound (single-shot semantics).
    let dbl = repos.invitations.mark_accepted(live.id, n).await;
    assert!(
        matches!(dbl, Err(RepoError::NotFound)),
        "expected NotFound on second mark_accepted, got {dbl:?}"
    );
}

#[tokio::test]
async fn invitation_list_pending_filters_accepted_and_expired() {
    let repos = fresh_backend().await;

    let user = repos.users.create(new_user("a@example.com")).await.unwrap();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let n = now();

    let pending = repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: "p@example.com".to_string(),
            role: "member".to_string(),
            token_hash: "pending-hash".to_string(),
            invited_by_user_id: user.id,
            expires_at: n + chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();

    let accepted = repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: "a@example.com".to_string(),
            role: "member".to_string(),
            token_hash: "accepted-hash".to_string(),
            invited_by_user_id: user.id,
            expires_at: n + chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();
    repos
        .invitations
        .mark_accepted(accepted.id, n)
        .await
        .unwrap();

    let _expired = repos
        .invitations
        .create(NewInvitation {
            id: Uuid::now_v7(),
            organization_id: org.id,
            email: "e@example.com".to_string(),
            role: "member".to_string(),
            token_hash: "stale-hash".to_string(),
            invited_by_user_id: user.id,
            expires_at: n - chrono::Duration::hours(1),
            accepted_at: None,
            created_at: n,
        })
        .await
        .unwrap();

    let listed = repos
        .invitations
        .list_pending_for_org(org.id)
        .await
        .unwrap();
    assert_eq!(
        listed.len(),
        1,
        "only the pending+live invitation should be returned, got {listed:?}"
    );
    assert_eq!(listed[0].id, pending.id);
}

// ---------------------------------------------------------------------------
// Cross-org isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn membership_does_not_leak_across_orgs() {
    let repos = fresh_backend().await;

    let alice = repos
        .users
        .create(new_user("alice@example.com"))
        .await
        .unwrap();
    let bob = repos
        .users
        .create(new_user("bob@example.com"))
        .await
        .unwrap();
    let org_a = repos.organizations.create(new_org("a")).await.unwrap();
    let org_b = repos.organizations.create(new_org("b")).await.unwrap();
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

    // Reverse lookup also isolates.
    let alice_orgs = repos.organizations.list_for_user(alice.id).await.unwrap();
    assert_eq!(alice_orgs.len(), 1);
    assert_eq!(alice_orgs[0].id, org_a.id);
}
