use super::*;

// Tests deliberately avoid printing token bytes in assertion
// messages — assertion failures end up in test logs / CI output,
// and a generated token is secret material by contract. `assert_eq!`
// without a trailing message keeps the diagnostic generic enough.

#[test]
fn generated_token_has_expected_shape() {
    let t = generate().unwrap();
    let s: &str = &t;
    assert!(s.starts_with(TOKEN_PREFIX));
    let hex_part = &s[TOKEN_PREFIX.len()..];
    assert_eq!(hex_part.len(), TOKEN_BYTES * 2);
    assert!(
        hex_part
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn each_call_returns_distinct_token() {
    // Not a strong entropy test — just guards against a static
    // accident (e.g. using a zero buffer).
    let a = generate().unwrap();
    let b = generate().unwrap();
    assert_ne!(&**a, &**b);
}

#[test]
fn no_trailing_whitespace_or_control_chars() {
    let t = generate().unwrap();
    let s: &str = &t;
    assert!(s.chars().all(|c| !c.is_control()));
    assert_eq!(s.trim(), s);
}
