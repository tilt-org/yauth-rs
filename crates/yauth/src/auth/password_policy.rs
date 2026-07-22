use crate::config::PasswordPolicyConfig;

/// Top 100 most common passwords (subset of SecLists). Checked when
/// `disallow_common_passwords` is enabled.
const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "121212",
    "000000",
    "qazwsx",
    "123qwe",
    "killer",
    "trustno1",
    "jordan",
    "jennifer",
    "zxcvbnm",
    "asdfgh",
    "hunter",
    "buster",
    "soccer",
    "harley",
    "batman",
    "andrew",
    "tigger",
    "sunshine",
    "iloveyou",
    "2000",
    "charlie",
    "robert",
    "thomas",
    "hockey",
    "ranger",
    "daniel",
    "starwars",
    "klaster",
    "112233",
    "george",
    "computer",
    "michelle",
    "jessica",
    "pepper",
    "1111",
    "zxcvbn",
    "555555",
    "11111111",
    "131313",
    "freedom",
    "777777",
    "pass",
    "maggie",
    "159753",
    "aaaaaa",
    "ginger",
    "princess",
    "joshua",
    "cheese",
    "amanda",
    "summer",
    "love",
    "ashley",
    "nicole",
    "chelsea",
    "biteme",
    "matthew",
    "access",
    "yankees",
    "987654321",
    "dallas",
    "austin",
    "thunder",
    "taylor",
    "matrix",
    "mobilemail",
    "admin",
    "passwd",
    "welcome",
    "passw0rd",
    "password1",
    "p@ssw0rd",
];

/// Standalone copy for the common-password check; kept out of the composed
/// "Password must …" sentence when it is the only violation.
const COMMON_PASSWORD_VIOLATION: &str =
    "This password is too common. Please choose a different one.";

/// Validate a password against the configured policy. Returns a list of violations
/// (empty = password is valid). Each violation is a "must …" fragment shaped to
/// slot into [`compose_message`]; the common-password check is the one
/// standalone sentence ([`COMMON_PASSWORD_VIOLATION`]).
pub fn validate(password: &str, config: &PasswordPolicyConfig) -> Vec<String> {
    let mut violations = Vec::new();

    if password.len() < config.min_length {
        violations.push(format!("be at least {} characters long", config.min_length));
    }

    if password.len() > config.max_length {
        violations.push(format!("be at most {} characters long", config.max_length));
    }

    if config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        violations.push("include an uppercase letter".into());
    }

    if config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        violations.push("include a lowercase letter".into());
    }

    if config.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        violations.push("include a number".into());
    }

    if config.require_special
        && !password
            .chars()
            .any(|c| !c.is_alphanumeric() && c.is_ascii())
    {
        violations.push("include a special character".into());
    }

    if config.disallow_common_passwords
        && COMMON_PASSWORDS.contains(&password.to_lowercase().as_str())
    {
        violations.push(COMMON_PASSWORD_VIOLATION.into());
    }

    violations
}

/// Compose the violations from [`validate`] into one human-readable sentence,
/// e.g. "Password must be at least 8 characters long and include an uppercase
/// letter, a number and a special character."
pub fn compose_message(violations: &[String]) -> String {
    let common = violations.iter().any(|v| v == COMMON_PASSWORD_VIOLATION);
    let mut fragments: Vec<String> = violations
        .iter()
        .filter(|v| *v != COMMON_PASSWORD_VIOLATION)
        .cloned()
        .collect();

    if fragments.is_empty() {
        return COMMON_PASSWORD_VIOLATION.to_string();
    }

    // Fold the "include X" fragments into a single clause so the sentence
    // reads "… include an uppercase letter, a number and a special character"
    // rather than repeating the verb.
    let includes: Vec<String> = fragments
        .iter()
        .filter_map(|f| f.strip_prefix("include "))
        .map(str::to_string)
        .collect();
    if includes.len() > 1 {
        fragments.retain(|f| !f.starts_with("include "));
        fragments.push(format!("include {}", join_natural(&includes)));
    }

    if common {
        fragments.push("not be a commonly used password".into());
    }

    format!("Password must {}.", join_natural(&fragments))
}

/// Join items with commas and a final "and": `a, b and c`.
fn join_natural(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [head @ .., last] => format!("{} and {}", head.join(", "), last),
    }
}

/// Check if a password matches any of the given historical password hashes.
pub fn check_password_history(password: &str, history_hashes: &[String]) -> bool {
    for hash in history_hashes {
        if crate::auth::password::verify_password_sync(password, hash).unwrap_or(false) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_policy() -> PasswordPolicyConfig {
        PasswordPolicyConfig {
            min_length: 8,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            disallow_common_passwords: true,
            password_history_count: 0,
        }
    }

    #[test]
    fn valid_password_passes() {
        let violations = validate("MyP@ssw0rd!", &strict_policy());
        assert!(violations.is_empty(), "violations: {:?}", violations);
    }

    #[test]
    fn missing_uppercase() {
        let violations = validate("myp@ssw0rd!", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("uppercase")));
    }

    #[test]
    fn missing_lowercase() {
        let violations = validate("MYP@SSW0RD!", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("lowercase")));
    }

    #[test]
    fn missing_digit() {
        let violations = validate("MyP@ssword!", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("number")));
    }

    #[test]
    fn missing_special() {
        let violations = validate("MyPassw0rd", &strict_policy());
        assert!(violations.iter().any(|v| v.contains("special")));
    }

    #[test]
    fn too_long() {
        let long = "a".repeat(200);
        let violations = validate(&long, &strict_policy());
        assert!(violations.iter().any(|v| v.contains("at most")));
    }

    #[test]
    fn common_password_rejected() {
        let policy = PasswordPolicyConfig {
            disallow_common_passwords: true,
            ..Default::default()
        };
        let violations = validate("password", &policy);
        assert!(violations.iter().any(|v| v.contains("common")));
    }

    #[test]
    fn common_password_case_insensitive() {
        let policy = PasswordPolicyConfig {
            disallow_common_passwords: true,
            ..Default::default()
        };
        let violations = validate("PASSWORD", &policy);
        assert!(violations.iter().any(|v| v.contains("common")));
    }

    #[test]
    fn compose_single_violation() {
        let violations = validate("myp@ssw0rd!", &strict_policy());
        assert_eq!(
            compose_message(&violations),
            "Password must include an uppercase letter."
        );
    }

    #[test]
    fn compose_merges_includes_into_one_clause() {
        // Missing uppercase, digit and special → one "include" clause.
        let violations = validate("mypassword", &strict_policy());
        assert_eq!(
            compose_message(&violations),
            "Password must include an uppercase letter, a number and a special character."
        );
    }

    #[test]
    fn compose_leads_with_length() {
        let violations = validate("short", &strict_policy());
        assert_eq!(
            compose_message(&violations),
            "Password must be at least 8 characters long and include an uppercase letter, \
             a number and a special character."
        );
    }

    #[test]
    fn compose_common_password_only_keeps_standalone_copy() {
        let policy = PasswordPolicyConfig {
            disallow_common_passwords: true,
            ..Default::default()
        };
        let violations = validate("password", &policy);
        assert_eq!(compose_message(&violations), COMMON_PASSWORD_VIOLATION);
    }

    #[test]
    fn compose_common_password_with_others_joins_in() {
        let violations = validate("password", &strict_policy());
        assert_eq!(
            compose_message(&violations),
            "Password must include an uppercase letter, a number and a special character \
             and not be a commonly used password."
        );
    }

    #[test]
    fn default_policy_allows_reasonable_password() {
        let violations = validate("reasonablepassword123", &PasswordPolicyConfig::default());
        assert!(violations.is_empty());
    }

    #[test]
    fn disabled_policy_allows_anything() {
        let policy = PasswordPolicyConfig {
            min_length: 0,
            max_length: 999,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            disallow_common_passwords: false,
            password_history_count: 0,
        };
        let violations = validate("a", &policy);
        assert!(violations.is_empty());
    }
}
