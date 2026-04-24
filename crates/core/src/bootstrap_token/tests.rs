use super::*;

#[test]
fn generated_token_has_expected_shape() {
    let t = generate().unwrap();
    let s: &str = &t;
    assert!(s.starts_with(TOKEN_PREFIX), "token = {s}");
    let hex_part = &s[TOKEN_PREFIX.len()..];
    assert_eq!(hex_part.len(), TOKEN_BYTES * 2);
    assert!(
        hex_part
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "non-hex char in {hex_part}"
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
    assert!(s.chars().all(|c| !c.is_control()), "control char: {s}");
    assert_eq!(s.trim(), s);
}
