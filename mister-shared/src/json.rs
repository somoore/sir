// ---------------------------------------------------------------------------
// Minimal JSON helpers (no serde, no external deps)
// ---------------------------------------------------------------------------

/// A minimal JSON value type for hand-rolled parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => {
                for (k, v) in entries {
                    if k == key {
                        return Some(v);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Serialize to JSON string.
    pub fn to_json_string(&self) -> String {
        match self {
            JsonValue::Null => "null".to_string(),
            JsonValue::Bool(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            JsonValue::Number(n) => {
                if *n == (*n as i64) as f64 {
                    format!("{}", *n as i64)
                } else {
                    format!("{}", n)
                }
            }
            JsonValue::Str(s) => format!("\"{}\"", json_escape(s)),
            JsonValue::Array(items) => {
                let parts: Vec<String> = items.iter().map(|v| v.to_json_string()).collect();
                format!("[{}]", parts.join(","))
            }
            JsonValue::Object(entries) => {
                let parts: Vec<String> = entries
                    .iter()
                    .map(|(k, v)| format!("\"{}\":{}", json_escape(k), v.to_json_string()))
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
        }
    }
}

pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Minimal JSON parser. Handles the subset needed for MSTR/1.
pub fn parse_json(input: &str) -> Result<JsonValue, String> {
    let input = input.trim();
    let chars: Vec<char> = input.chars().collect();
    let (val, pos) = parse_value(&chars, 0)?;
    let pos = skip_ws(&chars, pos);
    if pos < chars.len() {
        return Err("trailing junk after JSON value".to_string());
    }
    Ok(val)
}

fn skip_ws(chars: &[char], mut pos: usize) -> usize {
    while pos < chars.len() && chars[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

fn parse_value(chars: &[char], pos: usize) -> Result<(JsonValue, usize), String> {
    let pos = skip_ws(chars, pos);
    if pos >= chars.len() {
        return Err("unexpected end of input".to_string());
    }
    match chars[pos] {
        '"' => parse_string(chars, pos).map(|(s, p)| (JsonValue::Str(s), p)),
        '{' => parse_object(chars, pos),
        '[' => parse_array(chars, pos),
        't' | 'f' => parse_bool(chars, pos),
        'n' => parse_null(chars, pos),
        '-' | '0'..='9' => parse_number(chars, pos),
        c => Err(format!("unexpected char '{}' at position {}", c, pos)),
    }
}

// parse_string implements strict RFC 8259 §7 JSON string parsing:
//
//   - Only the nine defined escape sequences are accepted:
//     \" \\ \/ \b \f \n \r \t \uXXXX
//     Any other backslash escape (e.g. \x, \z, \') is an ERROR.
//     This used to be a silent passthrough — a tightened version of
//     the policy-parser is strictly correct now, not just permissive.
//
//   - Raw unescaped control characters (U+0000..U+001F) inside a
//     JSON string are rejected per §7: "All Unicode characters may
//     be placed within the quotation marks, except for the characters
//     that MUST be escaped: quotation mark, reverse solidus, and the
//     control characters (U+0000 through U+001F)."
//
//   - Lone UTF-16 surrogates are rejected. A leading surrogate
//     (U+D800..U+DBFF) must be immediately followed by a
//     \uXXXX escape for a trailing surrogate (U+DC00..U+DFFF); the
//     pair encodes a single non-BMP code point. A trailing surrogate
//     on its own, or a leading surrogate not followed by a valid
//     trailing surrogate, is an error.
//
// Rationale: the mister-core policy oracle takes adversary-influenced
// JSON over stdin. Strict parsing closes a class of fuzz-style bugs
// where a malformed string might silently produce a value that
// diverges from what the Go side saw. Better to reject the input and
// fail closed than to quietly pass a surprising value downstream.
fn parse_string(chars: &[char], pos: usize) -> Result<(String, usize), String> {
    if chars[pos] != '"' {
        return Err(format!("expected '\"' at {}", pos));
    }
    let mut i = pos + 1;
    let mut s = String::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            '"' => return Ok((s, i + 1)),
            '\\' => {
                i += 1;
                if i >= chars.len() {
                    return Err("unexpected end in string escape".to_string());
                }
                match chars[i] {
                    '"' => s.push('"'),
                    '\\' => s.push('\\'),
                    '/' => s.push('/'),
                    'b' => s.push('\u{0008}'),
                    'f' => s.push('\u{000C}'),
                    'n' => s.push('\n'),
                    'r' => s.push('\r'),
                    't' => s.push('\t'),
                    'u' => {
                        let (code_point, consumed) = parse_unicode_escape(chars, i + 1)?;
                        s.push(code_point);
                        i += consumed; // advance past the 4 hex digits (and a paired escape if any)
                    }
                    bad => {
                        return Err(format!("invalid escape sequence: \\{}", bad));
                    }
                }
            }
            // Raw control characters (U+0000..U+001F) are forbidden in
            // JSON strings per RFC 8259 §7. They must be represented as
            // \uXXXX escapes.
            ch if (ch as u32) < 0x20 => {
                return Err(format!(
                    "raw control character U+{:04X} in JSON string (must be escaped)",
                    ch as u32
                ));
            }
            ch => s.push(ch),
        }
        i += 1;
    }
    Err("unterminated string".to_string())
}

// parse_unicode_escape parses a 4-hex-digit Unicode escape starting at
// `pos` (which points to the first hex digit, i.e. the character AFTER
// the `\u`). Handles UTF-16 surrogate pairs by consuming a second
// \uXXXX escape when the first yields a leading surrogate.
//
// Returns (decoded char, number of input chars consumed after `pos`).
// The caller should add that count to its index.
fn parse_unicode_escape(chars: &[char], pos: usize) -> Result<(char, usize), String> {
    if pos + 4 > chars.len() {
        return Err("short unicode escape".to_string());
    }
    let hex: String = chars[pos..pos + 4].iter().collect();
    let cp = u32::from_str_radix(&hex, 16).map_err(|_| format!("bad unicode escape: {}", hex))?;

    // Leading surrogate — must be followed by \uXXXX trailing surrogate.
    if (0xD800..=0xDBFF).contains(&cp) {
        // Need the next 6 chars to be "\uXXXX".
        if pos + 4 + 6 > chars.len() || chars[pos + 4] != '\\' || chars[pos + 4 + 1] != 'u' {
            return Err(format!(
                "lone leading surrogate U+{:04X} (must be followed by \\uXXXX trailing surrogate)",
                cp
            ));
        }
        let hex2: String = chars[pos + 4 + 2..pos + 4 + 6].iter().collect();
        let cp2 =
            u32::from_str_radix(&hex2, 16).map_err(|_| format!("bad unicode escape: {}", hex2))?;
        if !(0xDC00..=0xDFFF).contains(&cp2) {
            return Err(format!(
                "leading surrogate U+{:04X} not followed by trailing surrogate (got U+{:04X})",
                cp, cp2
            ));
        }
        // Combine the surrogate pair into a single code point.
        let high = cp - 0xD800;
        let low = cp2 - 0xDC00;
        let combined = 0x10000 + (high << 10) + low;
        let ch = char::from_u32(combined).ok_or_else(|| {
            format!(
                "invalid code point from surrogate pair: U+{:04X} U+{:04X}",
                cp, cp2
            )
        })?;
        // Consumed chars relative to `i` (the 'u' position in the
        // outer loop): 4 hex digits + 2 ("\u") + 4 hex digits = 10.
        // The outer loop still adds +1 at the bottom, so we return
        // 10 here and the caller ends up 11 past 'u', which is
        // exactly the position after the trailing surrogate's last
        // hex digit (ready to match the next string character on
        // the next iteration).
        return Ok((ch, 10));
    }

    // Lone trailing surrogate — also invalid.
    if (0xDC00..=0xDFFF).contains(&cp) {
        return Err(format!(
            "lone trailing surrogate U+{:04X} (must be preceded by leading surrogate)",
            cp
        ));
    }

    // BMP code point. Consumed chars relative to `i` (the 'u'
    // position): 4 hex digits. Outer loop adds +1 at the bottom.
    let ch = char::from_u32(cp).ok_or_else(|| format!("invalid code point U+{:04X}", cp))?;
    Ok((ch, 4))
}

fn parse_number(chars: &[char], pos: usize) -> Result<(JsonValue, usize), String> {
    let mut i = pos;
    if i < chars.len() && chars[i] == '-' {
        i += 1;
    }
    while i < chars.len() && chars[i].is_ascii_digit() {
        i += 1;
    }
    if i < chars.len() && chars[i] == '.' {
        i += 1;
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < chars.len() && (chars[i] == 'e' || chars[i] == 'E') {
        i += 1;
        if i < chars.len() && (chars[i] == '+' || chars[i] == '-') {
            i += 1;
        }
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
    }
    let num_str: String = chars[pos..i].iter().collect();
    let n: f64 = num_str
        .parse()
        .map_err(|_| format!("bad number: {}", num_str))?;
    Ok((JsonValue::Number(n), i))
}

fn parse_bool(chars: &[char], pos: usize) -> Result<(JsonValue, usize), String> {
    if chars[pos..].starts_with(&['t', 'r', 'u', 'e']) {
        Ok((JsonValue::Bool(true), pos + 4))
    } else if chars[pos..].starts_with(&['f', 'a', 'l', 's', 'e']) {
        Ok((JsonValue::Bool(false), pos + 5))
    } else {
        Err(format!("expected bool at {}", pos))
    }
}

fn parse_null(chars: &[char], pos: usize) -> Result<(JsonValue, usize), String> {
    if chars[pos..].starts_with(&['n', 'u', 'l', 'l']) {
        Ok((JsonValue::Null, pos + 4))
    } else {
        Err(format!("expected null at {}", pos))
    }
}

fn parse_object(chars: &[char], pos: usize) -> Result<(JsonValue, usize), String> {
    let mut i = pos + 1; // skip '{'
    let mut entries = Vec::new();
    i = skip_ws(chars, i);
    if i < chars.len() && chars[i] == '}' {
        return Ok((JsonValue::Object(entries), i + 1));
    }
    loop {
        i = skip_ws(chars, i);
        let (key, next) = parse_string(chars, i)?;
        i = skip_ws(chars, next);
        if i >= chars.len() || chars[i] != ':' {
            return Err(format!("expected ':' at {}", i));
        }
        i += 1;
        let (val, next) = parse_value(chars, i)?;
        entries.push((key, val));
        i = skip_ws(chars, next);
        if i >= chars.len() {
            return Err("unterminated object".to_string());
        }
        if chars[i] == '}' {
            return Ok((JsonValue::Object(entries), i + 1));
        }
        if chars[i] != ',' {
            return Err(format!("expected ',' or '}}' at {}", i));
        }
        i += 1;
    }
}

fn parse_array(chars: &[char], pos: usize) -> Result<(JsonValue, usize), String> {
    let mut i = pos + 1; // skip '['
    let mut items = Vec::new();
    i = skip_ws(chars, i);
    if i < chars.len() && chars[i] == ']' {
        return Ok((JsonValue::Array(items), i + 1));
    }
    loop {
        let (val, next) = parse_value(chars, i)?;
        items.push(val);
        i = skip_ws(chars, next);
        if i >= chars.len() {
            return Err("unterminated array".to_string());
        }
        if chars[i] == ']' {
            return Ok((JsonValue::Array(items), i + 1));
        }
        if chars[i] != ',' {
            return Err(format!("expected ',' or ']' at {}", i));
        }
        i += 1;
        i = skip_ws(chars, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parse_object() {
        let json = r#"{"verb":"read_ref","target":".env","session_secret":false}"#;
        let val = parse_json(json).unwrap();
        assert_eq!(val.get("verb").unwrap().as_str(), Some("read_ref"));
        assert_eq!(val.get("target").unwrap().as_str(), Some(".env"));
        assert_eq!(val.get("session_secret").unwrap().as_bool(), Some(false));
    }

    #[test]
    fn test_json_parse_array() {
        let json = r#"[1, "two", true, null]"#;
        let val = parse_json(json).unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 4);
    }

    #[test]
    fn test_json_parse_nested() {
        let json = r#"{"labels":[{"sensitivity":"secret","trust":"trusted","provenance":"user"}]}"#;
        let val = parse_json(json).unwrap();
        let labels = val.get("labels").unwrap().as_array().unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(
            labels[0].get("sensitivity").unwrap().as_str(),
            Some("secret")
        );
    }

    #[test]
    fn test_json_escape_roundtrip() {
        let json = r#"{"msg":"hello \"world\"\nnewline"}"#;
        let val = parse_json(json).unwrap();
        assert_eq!(
            val.get("msg").unwrap().as_str(),
            Some("hello \"world\"\nnewline")
        );
    }

    #[test]
    fn test_json_rejects_trailing_junk() {
        let result = parse_json(r#"{"a":1}xyz"#);
        assert!(
            result.is_err(),
            "expected trailing-junk error, got {:?}",
            result
        );
        assert!(result.unwrap_err().contains("trailing junk"));
    }

    #[test]
    fn test_json_rejects_trailing_object() {
        let result = parse_json(r#"{"a":1}{"b":2}"#);
        assert!(
            result.is_err(),
            "expected trailing-object error, got {:?}",
            result
        );
    }

    #[test]
    fn test_json_accepts_trailing_whitespace() {
        let result = parse_json("{\"a\":1}  \n");
        assert!(
            result.is_ok(),
            "trailing whitespace should be accepted, got {:?}",
            result
        );
    }

    // ---- strict string-escape negative tests --------------------------
    //
    // These tests pin the post-refactor parse_string contract: unknown
    // escapes, raw control characters, and malformed surrogate escapes
    // must all be rejected rather than silently passed through.

    #[test]
    fn test_json_rejects_unknown_escape() {
        // \x is not a JSON escape. Pre-refactor the parser silently
        // kept \x in the output string. Now it must error.
        let result = parse_json(r#"{"s":"\x41"}"#);
        assert!(
            result.is_err(),
            "\\x escape should be rejected, got {:?}",
            result
        );
        let msg = format!("{:?}", result);
        assert!(
            msg.contains("invalid escape sequence"),
            "error should mention 'invalid escape sequence', got: {}",
            msg
        );
    }

    #[test]
    fn test_json_rejects_backslash_z() {
        let result = parse_json(r#"{"s":"\z"}"#);
        assert!(result.is_err(), "\\z should be rejected");
    }

    #[test]
    fn test_json_rejects_backslash_single_quote() {
        // RFC 8259 §7 does NOT list \' as a valid escape — single
        // quotes need no escaping in JSON strings (they are not
        // string delimiters).
        let result = parse_json(r#"{"s":"\'"}"#);
        assert!(result.is_err(), "\\' should be rejected");
    }

    // Helper: extract a string value from a JSON object by key.
    // The JsonValue type uses a Vec-of-tuples object representation
    // with a `Str` variant (not `String`), so the tests need a tiny
    // adapter to avoid repeating the iteration pattern below.
    fn get_str<'a>(val: &'a JsonValue, key: &str) -> Option<&'a str> {
        if let JsonValue::Object(pairs) = val {
            for (k, v) in pairs {
                if k == key {
                    if let JsonValue::Str(s) = v {
                        return Some(s);
                    }
                }
            }
        }
        None
    }

    #[test]
    fn test_json_accepts_all_defined_escapes() {
        // Positive check: the nine escapes RFC 8259 §7 defines must
        // all round-trip. \u0041 decodes to 'A'.
        let json = r#"{"s":"\"\\\/\b\f\n\r\t\u0041"}"#;
        let val = parse_json(json).unwrap();
        let s = get_str(&val, "s").expect("expected string for key 's'");
        assert_eq!(s, "\"\\/\u{0008}\u{000C}\n\r\tA");
    }

    #[test]
    fn test_json_rejects_raw_control_character() {
        // Raw \n (0x0A) inside a string literal is invalid JSON;
        // the JSON source must use the \n escape. Feed an unescaped
        // newline byte in the middle of a string and expect an error.
        let json = "{\"s\":\"line1\nline2\"}";
        let result = parse_json(json);
        assert!(
            result.is_err(),
            "raw control char in string should be rejected, got {:?}",
            result
        );
        let msg = format!("{:?}", result);
        assert!(
            msg.contains("control character"),
            "error should mention 'control character', got: {}",
            msg
        );
    }

    #[test]
    fn test_json_rejects_raw_tab() {
        let json = "{\"s\":\"a\tb\"}";
        let result = parse_json(json);
        assert!(result.is_err(), "raw tab in string should be rejected");
    }

    #[test]
    fn test_json_rejects_raw_null() {
        let json = "{\"s\":\"a\u{0000}b\"}";
        let result = parse_json(json);
        assert!(result.is_err(), "raw NUL in string should be rejected");
    }

    #[test]
    fn test_json_rejects_lone_leading_surrogate() {
        // U+D800 is the first code point in the leading-surrogate
        // range. On its own it is not a valid Unicode scalar — it
        // must be followed by a trailing surrogate in a \uXXXX\uXXXX
        // pair.
        let result = parse_json(r#"{"s":"\uD800"}"#);
        assert!(
            result.is_err(),
            "lone leading surrogate should be rejected, got {:?}",
            result
        );
        let msg = format!("{:?}", result);
        assert!(
            msg.contains("surrogate"),
            "error should mention 'surrogate', got: {}",
            msg
        );
    }

    #[test]
    fn test_json_rejects_lone_trailing_surrogate() {
        let result = parse_json(r#"{"s":"\uDC00"}"#);
        assert!(
            result.is_err(),
            "lone trailing surrogate should be rejected"
        );
    }

    #[test]
    fn test_json_rejects_leading_surrogate_not_followed_by_escape() {
        // Leading surrogate followed by something other than \u.
        let result = parse_json(r#"{"s":"\uD800x"}"#);
        assert!(
            result.is_err(),
            "leading surrogate followed by non-escape should be rejected"
        );
    }

    #[test]
    fn test_json_rejects_leading_surrogate_followed_by_bmp() {
        // Leading surrogate followed by a BMP escape is invalid —
        // the second half of a surrogate pair must itself be a
        // trailing surrogate (U+DC00..U+DFFF).
        let result = parse_json(r#"{"s":"\uD800\u0041"}"#);
        assert!(
            result.is_err(),
            "leading surrogate followed by BMP should be rejected"
        );
    }

    #[test]
    fn test_json_accepts_valid_surrogate_pair() {
        // U+1F600 (grinning face emoji) is encoded as the surrogate
        // pair \uD83D\uDE00. This is a positive test for the pair
        // handling we added.
        let json = r#"{"s":"\uD83D\uDE00"}"#;
        let val = parse_json(json).unwrap();
        let s = get_str(&val, "s").expect("expected string for key 's'");
        assert_eq!(s, "\u{1F600}");
    }

    #[test]
    fn test_json_short_unicode_escape() {
        let result = parse_json(r#"{"s":"\u00"}"#);
        assert!(result.is_err(), "short \\u escape should be rejected");
    }

    #[test]
    fn test_json_bad_hex_unicode_escape() {
        let result = parse_json(r#"{"s":"\uZZZZ"}"#);
        assert!(result.is_err(), "non-hex \\u escape should be rejected");
    }
}
