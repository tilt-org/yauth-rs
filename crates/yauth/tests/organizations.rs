//! Integration tests for the organizations primitive (issue #87).
//!
//! Validates the repository contracts against the in-memory backend. The
//! same suite should drop in for SQL backends once their concrete repos
//! land (tracked as follow-up issues).

#![cfg(all(
    feature = "memory-backend",
    feature = "organizations",
    feature = "email-password"
))]

use chrono::Utc;
use uuid::Uuid;

use yauth::backends::memory::InMemoryBackend;
use yauth::repo::{DatabaseBackend, RepoError};
use yauth_entity::{
    MembershipStatus, NewInvitation, NewMembership, NewOrganization, NewUser, UpdateOrganization,
};

fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

fn new_user(email: &str) -> NewUser {
    let now = now();
    NewUser {
        id: Uuid::now_v7(),
        email: email.to_string(),
        display_name: None,
        email_verified: true,
        role: "user".to_string(),
        banned: false,
        banned_reason: None,
        banned_until: None,
        created_at: now,
        updated_at: now,
    }
}

fn new_org(slug: &str) -> NewOrganization {
    let now = now();
    NewOrganization {
        id: Uuid::now_v7(),
        name: slug.to_string(),
        slug: slug.to_string(),
        display_name: None,
        avatar_url: None,
        metadata: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn org_create_find_update_delete_round_trip() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();

    let created = repos.organizations.create(new_org("acme")).await.unwrap();
    assert_eq!(created.slug, "acme");

    // Lookup by id
    let by_id = repos.organizations.find_by_id(created.id).await.unwrap();
    assert_eq!(by_id.unwrap().id, created.id);

    // Lookup by slug, case-insensitive
    let by_slug = repos.organizations.find_by_slug("ACME").await.unwrap();
    assert_eq!(by_slug.unwrap().id, created.id);

    // Update display name
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
}

#[tokio::test]
async fn org_slug_uniqueness_is_case_insensitive() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    repos.organizations.create(new_org("acme")).await.unwrap();
    let err = repos
        .organizations
        .create(new_org("ACME"))
        .await
        .unwrap_err();
    assert!(matches!(err, RepoError::Conflict(_)));
}

#[tokio::test]
async fn membership_uniqueness_and_listing() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();

    let user = repos.users.create(new_user("a@example.com")).await.unwrap();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    let now = now();
    let m = repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org.id,
            user_id: user.id,
            role: "admin".to_string(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    // Duplicate (org, user) rejected.
    let dup = repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: org.id,
            user_id: user.id,
            role: "member".to_string(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await;
    assert!(matches!(dup, Err(RepoError::Conflict(_))));

    // List by org and by user.
    let by_org = repos.memberships.list_by_org(org.id).await.unwrap();
    assert_eq!(by_org.len(), 1);
    assert_eq!(by_org[0].id, m.id);

    let by_user = repos.memberships.list_by_user(user.id).await.unwrap();
    assert_eq!(by_user.len(), 1);
}

#[tokio::test]
async fn org_list_for_user_returns_only_joined_orgs() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();

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

#[tokio::test]
async fn org_delete_cascades_to_memberships_and_invitations() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();

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
            token_hash: "deadbeef".to_string(),
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
async fn invitation_token_lookup_filters_expired_and_accepted() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();

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

    // Live token returns Some.
    assert!(
        repos
            .invitations
            .find_by_token_hash("live-hash")
            .await
            .unwrap()
            .is_some()
    );

    // Expired token returns None.
    assert!(
        repos
            .invitations
            .find_by_token_hash("expired-hash")
            .await
            .unwrap()
            .is_none()
    );

    // After acceptance, live token no longer resolves.
    repos.invitations.mark_accepted(live.id, n).await.unwrap();
    assert!(
        repos
            .invitations
            .find_by_token_hash("live-hash")
            .await
            .unwrap()
            .is_none()
    );

    // Double-accept returns NotFound.
    let dbl = repos.invitations.mark_accepted(live.id, n).await;
    assert!(matches!(dbl, Err(RepoError::NotFound)));
}

/// Cross-org isolation: a user who is a member of org A must not appear in
/// memberships listed for org B. This is the basic membership-primitive
/// probe; richer cross-org coverage lands when RBAC (issue #88) ships.
#[tokio::test]
async fn membership_does_not_leak_across_orgs() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();

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

    for (user, org) in [(alice.id, org_a.id), (bob.id, org_b.id)] {
        repos
            .memberships
            .create(NewMembership {
                id: Uuid::now_v7(),
                organization_id: org,
                user_id: user,
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
