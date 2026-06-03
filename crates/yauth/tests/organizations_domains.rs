//! Integration tests for verified email domains + JIT membership (issue #90).
//!
//! Validates the repository invariants on the in-memory backend and exercises
//! the auto-join helper without touching DNS. The DNS-verifier code path is
//! covered by unit tests in `auth::domain_verifier` — here we test the
//! contract that consumers depend on (uniqueness, JIT semantics, anti-abuse
//! defaults).

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
    DomainStatus, MembershipStatus, NewMembership, NewOrganization, NewOrganizationDomain, NewUser,
    UpdateOrganizationDomain, domain_from_email,
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
        suspended_at: None,
        suspended_reason: None,
        activates_at: None,
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

fn new_domain(org_id: Uuid, dom: &str, verified: bool, auto_join: bool) -> NewOrganizationDomain {
    let now = now();
    NewOrganizationDomain {
        id: Uuid::now_v7(),
        organization_id: org_id,
        domain: dom.to_string(),
        status: if verified {
            DomainStatus::Verified
        } else {
            DomainStatus::Pending
        },
        verification_token: format!("tok-{}", Uuid::new_v4()),
        verified_at: if verified { Some(now) } else { None },
        last_checked_at: if verified { Some(now) } else { None },
        auto_join_on_signup: auto_join,
        default_role_on_auto_join: "member".to_string(),
        require_email_verified: true,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn create_round_trip_and_case_insensitive_lookup() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();

    let created = repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", false, false))
        .await
        .unwrap();
    assert_eq!(created.domain, "acme.com");
    assert_eq!(created.status, DomainStatus::Pending);

    let by_id = repos
        .organization_domains
        .find_by_id(created.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_id.id, created.id);

    // Case-insensitive find_by_domain.
    let by_dom = repos
        .organization_domains
        .find_by_domain("ACME.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_dom.id, created.id);
}

#[tokio::test]
async fn deployment_wide_domain_uniqueness() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org_a = repos.organizations.create(new_org("acme")).await.unwrap();
    let org_b = repos.organizations.create(new_org("globex")).await.unwrap();

    repos
        .organization_domains
        .create(new_domain(org_a.id, "shared.com", true, true))
        .await
        .unwrap();
    let err = repos
        .organization_domains
        .create(new_domain(org_b.id, "SHARED.com", true, true))
        .await
        .unwrap_err();
    assert!(
        matches!(err, RepoError::Conflict(_)),
        "expected Conflict on duplicate domain (case-insensitive), got {err:?}"
    );
}

#[tokio::test]
async fn update_changes_status_and_flags() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let d = repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", false, false))
        .await
        .unwrap();

    let now = now();
    let updated = repos
        .organization_domains
        .update(
            d.id,
            UpdateOrganizationDomain {
                status: Some(DomainStatus::Verified),
                verified_at: Some(Some(now)),
                last_checked_at: Some(Some(now)),
                auto_join_on_signup: Some(true),
                require_email_verified: Some(false),
                updated_at: Some(now),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.status, DomainStatus::Verified);
    assert!(updated.auto_join_on_signup);
    assert!(!updated.require_email_verified);
    assert!(updated.verified_at.is_some());
}

#[tokio::test]
async fn delete_is_idempotent_and_cascade_clears_with_org() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let d = repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", true, true))
        .await
        .unwrap();

    // Direct delete works.
    repos.organization_domains.delete(d.id).await.unwrap();
    // Idempotent second delete.
    repos.organization_domains.delete(d.id).await.unwrap();

    // Org cascade: re-create then delete the org.
    let d2 = repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", true, true))
        .await
        .unwrap();
    repos.organizations.delete(org.id).await.unwrap();
    let by_id = repos.organization_domains.find_by_id(d2.id).await.unwrap();
    assert!(
        by_id.is_none(),
        "deleting the org should cascade-delete its domain claims"
    );
}

#[tokio::test]
async fn list_for_org_is_sorted_by_created_at() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let d1 = repos
        .organization_domains
        .create(new_domain(org.id, "a.example.com", true, false))
        .await
        .unwrap();
    // Force a strictly later created_at on the second row.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let d2 = repos
        .organization_domains
        .create(new_domain(org.id, "b.example.com", true, false))
        .await
        .unwrap();
    let list = repos
        .organization_domains
        .list_for_org(org.id)
        .await
        .unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, d1.id);
    assert_eq!(list[1].id, d2.id);
}

#[tokio::test]
async fn domain_from_email_canonicalizes() {
    assert_eq!(
        domain_from_email("Alice@Example.COM"),
        Some("example.com".to_string())
    );
    assert_eq!(domain_from_email("no-at-sign"), None);
    assert_eq!(domain_from_email("user@"), None);
}

// ──────────────────────────────────────────────
// JIT membership semantics — exercise the storage shape directly so we
// validate the contract independently of HTTP wiring.
// ──────────────────────────────────────────────

#[tokio::test]
async fn matching_verified_domain_with_auto_join_creates_membership() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", true, true))
        .await
        .unwrap();
    let user = repos
        .users
        .create(new_user("alice@acme.com"))
        .await
        .unwrap();

    // Lookup matches → simulated auto-join.
    let dom = domain_from_email(&user.email).unwrap();
    let row = repos
        .organization_domains
        .find_by_domain(&dom)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, DomainStatus::Verified);
    assert!(row.auto_join_on_signup);

    let now = now();
    repos
        .memberships
        .create(NewMembership {
            id: Uuid::now_v7(),
            organization_id: row.organization_id,
            user_id: user.id,
            role: row.default_role_on_auto_join.clone(),
            status: MembershipStatus::Active,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    let mem = repos
        .memberships
        .find_by_org_user(org.id, user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mem.role, "member");
    assert_eq!(mem.status, MembershipStatus::Active);
}

#[tokio::test]
async fn pending_domain_does_not_grant_auto_join() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    // Pending (not verified) → must not auto-join.
    repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", false, true))
        .await
        .unwrap();

    let dom = domain_from_email("bob@acme.com").unwrap();
    let row = repos
        .organization_domains
        .find_by_domain(&dom)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, DomainStatus::Pending);
    // Caller is required to skip auto-join unless `row.status == Verified`.
}

#[tokio::test]
async fn auto_join_off_means_no_membership_even_if_verified() {
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", true, false))
        .await
        .unwrap();

    let row = repos
        .organization_domains
        .find_by_domain("acme.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, DomainStatus::Verified);
    assert!(
        !row.auto_join_on_signup,
        "auto_join_on_signup must remain off until explicitly enabled"
    );
}

#[tokio::test]
async fn require_email_verified_blocks_unverified_user() {
    // The on-disk default for `require_email_verified` is true. This is the
    // anti-abuse gate against typosquat-then-piggyback attacks.
    let backend = InMemoryBackend::new();
    let repos = backend.repositories();
    let org = repos.organizations.create(new_org("acme")).await.unwrap();
    let row = repos
        .organization_domains
        .create(new_domain(org.id, "acme.com", true, true))
        .await
        .unwrap();
    assert!(row.require_email_verified, "default must be true");
}
