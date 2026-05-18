//! Minimal SCIM filter parser (RFC 7644 §3.4.2.2 subset).
//!
//! Supported syntax:
//!
//! ```text
//! filter      = expr (SP "and" SP expr)*
//! expr        = attr SP op SP value
//! op          = "eq" / "co" / "sw"
//! value       = quoted-string / boolean / number
//! ```
//!
//! Examples:
//!
//! - `userName eq "alice@acme.com"`
//! - `displayName co "Alice"`
//! - `userName sw "a" and active eq true`
//!
//! Unsupported tokens (`or`, `pr`, `gt`, parens, nested attributes
//! like `emails[type eq "work"].value`) are rejected with
//! `invalidFilter` so callers don't silently get incomplete results.
//!
//! Why hand-rolled? SCIM is the only place yauth needs a filter
//! language. A general parser-combinator dep would dwarf the actual
//! requirement (three operators + AND). Recursive descent is ~150 LoC
//! and trivial to fuzz.

#![forbid(unsafe_code)]

use super::types::ScimError;

/// A single matchable predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterAtom {
    /// Attribute path. Case-insensitive per SCIM — handlers compare
    /// against a fixed list of lowercase known attribute names.
    pub attr: String,
    pub op: FilterOp,
    pub value: FilterValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    /// Exact match (case-insensitive for strings).
    Eq,
    /// Substring contains.
    Co,
    /// Starts-with.
    Sw,
}

/// Typed RHS value. `Boolean`/`Number` round-trip the lexical form, so
/// `active eq true` and `active eq false` map to clear booleans rather
/// than to the strings `"true"` / `"false"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterValue {
    String(String),
    Boolean(bool),
    Number(i64),
}

impl FilterValue {
    /// Compare two strings under the operator. For `Eq`, comparison is
    /// case-insensitive (RFC 7644 §3.4.2.2 — `caseExact: false`
    /// defaults).
    pub fn matches_string(&self, op: FilterOp, candidate: &str) -> bool {
        let needle = match self {
            FilterValue::String(s) => s.as_str(),
            FilterValue::Boolean(b) => {
                return op == FilterOp::Eq
                    && candidate.eq_ignore_ascii_case(b.to_string().as_str());
            }
            FilterValue::Number(n) => {
                return op == FilterOp::Eq && candidate == n.to_string();
            }
        };
        match op {
            FilterOp::Eq => candidate.eq_ignore_ascii_case(needle),
            FilterOp::Co => candidate
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            FilterOp::Sw => candidate
                .to_ascii_lowercase()
                .starts_with(&needle.to_ascii_lowercase()),
        }
    }

    pub fn matches_bool(&self, op: FilterOp, candidate: bool) -> bool {
        if op != FilterOp::Eq {
            return false;
        }
        match self {
            FilterValue::Boolean(b) => *b == candidate,
            FilterValue::String(s) => {
                s.eq_ignore_ascii_case(if candidate { "true" } else { "false" })
            }
            FilterValue::Number(_) => false,
        }
    }
}

/// Parsed top-level filter — a non-empty list of atoms joined by AND.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub atoms: Vec<FilterAtom>,
}

impl Filter {
    pub fn matches<F>(&self, resolve: F) -> bool
    where
        F: FnMut(&FilterAtom) -> bool,
    {
        self.atoms.iter().all(resolve)
    }
}

// ──────────────────────────────────────────────
// Parser
// ──────────────────────────────────────────────

/// Parse a filter string. Returns a SCIM-shaped `ScimError` on
/// rejection.
pub fn parse(input: &str) -> Result<Filter, ScimError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid_filter("empty filter"));
    }
    let mut parser = Parser::new(trimmed);
    let f = parser.parse_filter()?;
    parser.expect_eof()?;
    Ok(f)
}

fn invalid_filter(detail: impl Into<String>) -> ScimError {
    ScimError::new(400, Some("invalidFilter"), detail)
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            src: input.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    /// Read an identifier (`[A-Za-z][A-Za-z0-9_.]*`). Attribute paths
    /// like `name.givenName` are returned as-is — callers downcase
    /// before matching.
    fn read_ident(&mut self) -> Result<String, ScimError> {
        self.skip_ws();
        let start = self.pos;
        match self.peek() {
            Some(c) if (c as char).is_ascii_alphabetic() => {}
            _ => return Err(invalid_filter("expected attribute name")),
        }
        while let Some(c) = self.peek() {
            let ch = c as char;
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let slice = &self.src[start..self.pos];
        // SAFETY: filter is parsed from a &str, but `Parser` works on bytes —
        // the slice is guaranteed UTF-8 because we only advanced over ASCII.
        let s = std::str::from_utf8(slice)
            .map_err(|_| invalid_filter("attribute name not valid UTF-8"))?;
        Ok(s.to_string())
    }

    /// Read a lowercase keyword (operator or `and`). Returns the
    /// matched keyword if it equals `expected` (case-insensitive),
    /// otherwise resets position and returns `None`.
    fn match_keyword(&mut self, expected: &str) -> bool {
        self.skip_ws();
        let bytes = expected.as_bytes();
        if self.pos + bytes.len() > self.src.len() {
            return false;
        }
        // Match case-insensitively.
        for (i, b) in bytes.iter().enumerate() {
            if !self.src[self.pos + i].eq_ignore_ascii_case(b) {
                return false;
            }
        }
        // Must be terminated by whitespace or EOF — otherwise `and`
        // could match the start of `andrew`.
        let next = self.src.get(self.pos + bytes.len()).copied();
        if let Some(c) = next
            && !matches!(c, b' ' | b'\t' | b'(')
        {
            return false;
        }
        self.pos += bytes.len();
        true
    }

    fn read_op(&mut self) -> Result<FilterOp, ScimError> {
        self.skip_ws();
        // Read up to the next whitespace.
        let start = self.pos;
        while let Some(c) = self.peek() {
            if (c as char).is_ascii_alphabetic() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let op_str = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| invalid_filter("operator not valid UTF-8"))?
            .to_ascii_lowercase();
        match op_str.as_str() {
            "eq" => Ok(FilterOp::Eq),
            "co" => Ok(FilterOp::Co),
            "sw" => Ok(FilterOp::Sw),
            "" => Err(invalid_filter("missing comparison operator")),
            "ne" | "gt" | "ge" | "lt" | "le" | "pr" | "ew" => Err(invalid_filter(format!(
                "operator '{op_str}' is not supported (only eq, co, sw)"
            ))),
            other => Err(invalid_filter(format!("unknown operator: {other}"))),
        }
    }

    fn read_value(&mut self) -> Result<FilterValue, ScimError> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.read_quoted_string().map(FilterValue::String),
            Some(b't') | Some(b'T') if self.match_keyword("true") => Ok(FilterValue::Boolean(true)),
            Some(b'f') | Some(b'F') if self.match_keyword("false") => {
                Ok(FilterValue::Boolean(false))
            }
            Some(c) if (c as char).is_ascii_digit() || c == b'-' => self.read_number(),
            _ => Err(invalid_filter(
                "expected quoted string, boolean, or number on RHS",
            )),
        }
    }

    fn read_quoted_string(&mut self) -> Result<String, ScimError> {
        // Consume opening quote.
        if self.bump() != Some(b'"') {
            return Err(invalid_filter("expected opening quote"));
        }
        let mut out = String::new();
        while let Some(c) = self.bump() {
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self
                        .bump()
                        .ok_or_else(|| invalid_filter("dangling escape"))?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        // SCIM doesn't formally specify Unicode escapes;
                        // we reject them rather than over-accept and
                        // give an attacker a side channel.
                        _ => return Err(invalid_filter("unsupported escape sequence")),
                    }
                }
                _ => out.push(c as char),
            }
        }
        Err(invalid_filter("unterminated string literal"))
    }

    fn read_number(&mut self) -> Result<FilterValue, ScimError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if (c as char).is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let slice = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| invalid_filter("number not valid UTF-8"))?;
        slice
            .parse::<i64>()
            .map(FilterValue::Number)
            .map_err(|_| invalid_filter(format!("invalid number: {slice}")))
    }

    fn parse_atom(&mut self) -> Result<FilterAtom, ScimError> {
        let attr = self.read_ident()?;
        let op = self.read_op()?;
        let value = self.read_value()?;
        Ok(FilterAtom { attr, op, value })
    }

    fn parse_filter(&mut self) -> Result<Filter, ScimError> {
        let first = self.parse_atom()?;
        let mut atoms = vec![first];
        loop {
            self.skip_ws();
            if self.peek().is_none() {
                break;
            }
            if self.match_keyword("and") {
                atoms.push(self.parse_atom()?);
                continue;
            }
            if self.match_keyword("or") {
                return Err(invalid_filter(
                    "'or' is not supported — only 'and' joins multiple predicates",
                ));
            }
            return Err(invalid_filter(format!(
                "unexpected character at position {}",
                self.pos
            )));
        }
        Ok(Filter { atoms })
    }

    fn expect_eof(&mut self) -> Result<(), ScimError> {
        self.skip_ws();
        if self.pos < self.src.len() {
            return Err(invalid_filter(format!(
                "trailing input at position {}",
                self.pos
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_eq_string() {
        let f = parse("userName eq \"alice@acme.com\"").unwrap();
        assert_eq!(f.atoms.len(), 1);
        assert_eq!(f.atoms[0].attr, "userName");
        assert_eq!(f.atoms[0].op, FilterOp::Eq);
        assert_eq!(
            f.atoms[0].value,
            FilterValue::String("alice@acme.com".into())
        );
    }

    #[test]
    fn parse_co() {
        let f = parse("displayName co \"Alice\"").unwrap();
        assert_eq!(f.atoms[0].op, FilterOp::Co);
    }

    #[test]
    fn parse_sw() {
        let f = parse("userName sw \"al\"").unwrap();
        assert_eq!(f.atoms[0].op, FilterOp::Sw);
    }

    #[test]
    fn parse_boolean() {
        let f = parse("active eq true").unwrap();
        assert_eq!(f.atoms[0].value, FilterValue::Boolean(true));
        let g = parse("active eq false").unwrap();
        assert_eq!(g.atoms[0].value, FilterValue::Boolean(false));
    }

    #[test]
    fn parse_and_chain() {
        let f = parse("userName sw \"al\" and active eq true").unwrap();
        assert_eq!(f.atoms.len(), 2);
        assert_eq!(f.atoms[0].op, FilterOp::Sw);
        assert_eq!(f.atoms[1].attr, "active");
    }

    #[test]
    fn rejects_or() {
        let e = parse("a eq \"x\" or b eq \"y\"").unwrap_err();
        assert_eq!(e.status, "400");
        assert_eq!(e.scim_type.as_deref(), Some("invalidFilter"));
    }

    #[test]
    fn rejects_gt() {
        let e = parse("createdAt gt 1234").unwrap_err();
        assert!(e.detail.as_ref().unwrap().contains("not supported"));
    }

    #[test]
    fn rejects_unterminated_string() {
        let e = parse("userName eq \"alice").unwrap_err();
        assert!(e.detail.as_ref().unwrap().contains("unterminated"));
    }

    #[test]
    fn rejects_sql_injection_attempt() {
        // SQL fragment with an embedded quote escape pattern — the
        // parser must either accept it as a literal string or reject
        // cleanly, never panic.
        let e = parse("userName eq \"alice\\\"; DROP TABLE users\"");
        match e {
            Ok(f) => {
                // If accepted, the content is preserved verbatim — the
                // semicolon does NOT leak into any downstream query.
                assert_eq!(
                    f.atoms[0].value,
                    FilterValue::String("alice\"; DROP TABLE users".into())
                );
            }
            Err(err) => {
                // Equally acceptable — the test asserts no panic and a
                // SCIM error shape.
                assert_eq!(err.status, "400");
            }
        }
    }

    #[test]
    fn rejects_backtick_smuggling() {
        // Backticks aren't valid SCIM syntax — should reject.
        let e = parse("userName eq `alice`");
        match e {
            Ok(_) => panic!("backticks must not be valid filter syntax"),
            Err(err) => assert_eq!(err.status, "400"),
        }
    }

    #[test]
    fn rejects_empty() {
        let e = parse("").unwrap_err();
        assert!(e.detail.as_ref().unwrap().contains("empty"));
    }

    #[test]
    fn case_insensitive_op() {
        let f = parse("userName EQ \"x\"").unwrap();
        assert_eq!(f.atoms[0].op, FilterOp::Eq);
        let g = parse("userName sW \"x\"").unwrap();
        assert_eq!(g.atoms[0].op, FilterOp::Sw);
    }

    #[test]
    fn matches_eq_case_insensitive() {
        let v = FilterValue::String("Alice".into());
        assert!(v.matches_string(FilterOp::Eq, "alice"));
        assert!(v.matches_string(FilterOp::Eq, "ALICE"));
    }

    #[test]
    fn matches_co_substring() {
        let v = FilterValue::String("Wonder".into());
        assert!(v.matches_string(FilterOp::Co, "Alice Wonderland"));
        assert!(!v.matches_string(FilterOp::Co, "Bob"));
    }

    #[test]
    fn matches_sw_prefix() {
        let v = FilterValue::String("ali".into());
        assert!(v.matches_string(FilterOp::Sw, "Alice@example"));
        assert!(!v.matches_string(FilterOp::Sw, "Bob"));
    }

    #[test]
    fn matches_bool() {
        let v = FilterValue::Boolean(true);
        assert!(v.matches_bool(FilterOp::Eq, true));
        assert!(!v.matches_bool(FilterOp::Eq, false));
    }
}
