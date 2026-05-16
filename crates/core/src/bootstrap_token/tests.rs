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
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
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

#[test]
fn hash_verifies_original_token_only() {
    let token = generate().unwrap();
    let stored = hash_for_storage(&token).unwrap();

    assert!(stored.starts_with(TOKEN_HASH_PREFIX));
    assert!(verify_against_hash(&token, &stored).unwrap());

    let other = generate().unwrap();
    assert!(!verify_against_hash(&other, &stored).unwrap());
}

#[test]
fn hash_rejects_plaintext_token_shape_errors() {
    assert!(matches!(
        hash_for_storage("wrong"),
        Err(TokenFormatError::InvalidToken)
    ));
    assert!(matches!(
        hash_for_storage("dby_boot_ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEF"),
        Err(TokenFormatError::InvalidToken)
    ));
}

#[test]
fn verify_rejects_hash_shape_errors() {
    let token = generate().unwrap();
    assert!(matches!(
        verify_against_hash(&token, "dby_boot_plaintext"),
        Err(TokenFormatError::InvalidHash)
    ));
}
