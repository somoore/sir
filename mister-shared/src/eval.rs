// ---------------------------------------------------------------------------
// Evaluation Request/Response and supporting Sink/LeaseResource types
// ---------------------------------------------------------------------------

use crate::json::{json_escape, parse_json, JsonValue};
use crate::labels::{Label, Provenance, RiskTier, Sensitivity, TrustLevel, Verdict};

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sink {
    pub pattern: String,
    pub trust: TrustLevel,
    pub min_risk: RiskTier,
}

// ---------------------------------------------------------------------------
// Lease Resource
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseResource {
    pub pattern: String,
    pub permissions: Vec<String>,
    pub resource_kind: String,
}

// ---------------------------------------------------------------------------
// Evaluation Request (sent from Go to Rust via MSTR/1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EvalRequest {
    pub verb: String,
    pub target: String,
    pub tool_name: String,
    pub labels: Vec<Label>,
    pub derived_labels: Vec<Label>,
    pub session_secret: bool,
    pub session_untrusted_read: bool,
    pub is_posture_file: bool,
    pub is_sensitive_path: bool,
    pub is_delegation: bool,
    pub is_tripwire: bool,
}

// ---------------------------------------------------------------------------
// Evaluation Response (sent from Rust to Go via MSTR/1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EvalResponse {
    pub verdict: Verdict,
    pub reason: String,
    pub risk_tier: RiskTier,
    pub labels_applied: Vec<Label>,
    pub receipt_id: String,
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Session context (sent from Go to Rust via MSTR/1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EvalSessionContext {
    pub secret_session: bool,
    pub recently_read_untrusted: bool,
    pub deny_all: bool,
    pub approval_scope: String,
    pub turn_counter: u64,
}

// ---------------------------------------------------------------------------
// Request/Response JSON serialization
// ---------------------------------------------------------------------------

impl EvalRequest {
    /// Deserialize from JSON string.
    ///
    /// Required fields (must be present and string-typed): `tool_name`, `verb`, `target`.
    /// These come from `pkg/core/core.go`'s MSTR/1 protocol bridge — every well-formed
    /// request from Go always populates them. A missing or wrong-typed required field
    /// is a bug in the caller and must fail closed.
    ///
    /// Optional bool fields default to `false` if absent: `is_posture_file`,
    /// `is_sensitive_path`, `is_delegation`, `is_tripwire`, `session_secret`,
    /// `session_untrusted_read`. If present, they must be bool-typed.
    ///
    /// Optional label arrays default to empty if absent: `labels`, `derived_labels`.
    /// If present, every entry must be well-formed.
    ///
    /// Unknown fields are silently ignored for forward compatibility — the Go layer
    /// may add new fields before the Rust core learns about them.
    pub fn from_json(s: &str) -> Result<Self, String> {
        let val = parse_json(s)?;

        // Required string fields. Missing or wrong-type → error.
        fn require_str(val: &JsonValue, key: &str) -> Result<String, String> {
            match val.get(key) {
                None => Err(format!("missing required field '{}'", key)),
                Some(v) => match v.as_str() {
                    Some(s) => Ok(s.to_string()),
                    None => Err(format!("field '{}' must be a string", key)),
                },
            }
        }

        // Optional bool fields. Missing → default. Present but wrong-type → error.
        fn opt_bool(val: &JsonValue, key: &str) -> Result<bool, String> {
            match val.get(key) {
                None => Ok(false),
                Some(JsonValue::Bool(b)) => Ok(*b),
                Some(_) => Err(format!("field '{}' must be a boolean", key)),
            }
        }

        let tool_name = require_str(&val, "tool_name")?;
        let verb = require_str(&val, "verb")?;
        let target = require_str(&val, "target")?;

        let session_secret = opt_bool(&val, "session_secret")?;
        let session_untrusted_read = opt_bool(&val, "session_untrusted_read")?;
        let is_posture_file = opt_bool(&val, "is_posture_file")?;
        let is_sensitive_path = opt_bool(&val, "is_sensitive_path")?;
        let is_delegation = opt_bool(&val, "is_delegation")?;
        let is_tripwire = opt_bool(&val, "is_tripwire")?;

        // Labels: optional, but when present every entry must be well-formed.
        // Previously this was a silent filter_map drop — an attacker or a
        // buggy caller producing malformed label entries would see their
        // labels disappear, which could downgrade the effective Sensitivity
        // of a request (e.g., a "Secret" label dropped to the default
        // Public label, weakening IFC check_flow). Fail closed instead:
        // any malformed label entry rejects the whole request.
        fn parse_label(lv: &JsonValue) -> Result<Label, String> {
            let sens_str = lv
                .get("sensitivity")
                .and_then(|v| v.as_str())
                .ok_or("label missing 'sensitivity' field")?;
            let sens = Sensitivity::from_str(sens_str)
                .ok_or_else(|| format!("label has unknown sensitivity '{}'", sens_str))?;
            let trust_str = lv
                .get("trust")
                .and_then(|v| v.as_str())
                .ok_or("label missing 'trust' field")?;
            let trust = TrustLevel::from_str(trust_str)
                .ok_or_else(|| format!("label has unknown trust level '{}'", trust_str))?;
            let prov_str = lv
                .get("provenance")
                .and_then(|v| v.as_str())
                .ok_or("label missing 'provenance' field")?;
            let prov = Provenance::from_str(prov_str)
                .ok_or_else(|| format!("label has unknown provenance '{}'", prov_str))?;
            Ok(Label::new(sens, trust, prov))
        }

        fn parse_label_array(val: &JsonValue, key: &str) -> Result<Vec<Label>, String> {
            match val.get(key) {
                None => Ok(Vec::new()),
                Some(v) => match v.as_array() {
                    Some(arr) => {
                        let mut out = Vec::with_capacity(arr.len());
                        for lv in arr.iter() {
                            out.push(parse_label(lv)?);
                        }
                        Ok(out)
                    }
                    None => Err(format!("field '{}' must be an array", key)),
                },
            }
        }

        let labels = parse_label_array(&val, "labels")?;
        let derived_labels = parse_label_array(&val, "derived_labels")?;

        Ok(EvalRequest {
            verb,
            target,
            tool_name,
            labels,
            derived_labels,
            session_secret,
            session_untrusted_read,
            is_posture_file,
            is_sensitive_path,
            is_delegation,
            is_tripwire,
        })
    }

    /// Return all labels relevant to this request, including lineage-derived
    /// labels that were attached at sink time.
    pub fn effective_labels(&self) -> Vec<Label> {
        let mut out = Vec::with_capacity(self.labels.len() + self.derived_labels.len());
        out.extend(self.labels.iter().cloned());
        out.extend(self.derived_labels.iter().cloned());
        out
    }

    /// Whether the request carries lineage proving the sink touches secret-derived data.
    pub fn has_derived_secret(&self) -> bool {
        self.derived_labels
            .iter()
            .any(|label| label.sensitivity == Sensitivity::Secret)
    }
}

impl EvalSessionContext {
    /// Deserialize the top-level session object from the MSTR/1 envelope.
    ///
    /// All fields are optional for forward/backward compatibility. Missing
    /// booleans default to `false`, approval_scope defaults to the empty
    /// string, and turn_counter defaults to 0.
    pub fn from_json(s: &str) -> Result<Self, String> {
        let val = parse_json(s)?;

        fn opt_bool(val: &JsonValue, key: &str) -> Result<bool, String> {
            match val.get(key) {
                None => Ok(false),
                Some(JsonValue::Bool(b)) => Ok(*b),
                Some(_) => Err(format!("field '{}' must be a boolean", key)),
            }
        }

        fn opt_string(val: &JsonValue, key: &str) -> Result<String, String> {
            match val.get(key) {
                None => Ok(String::new()),
                Some(v) => match v.as_str() {
                    Some(s) => Ok(s.to_string()),
                    None => Err(format!("field '{}' must be a string", key)),
                },
            }
        }

        fn opt_u64(val: &JsonValue, key: &str) -> Result<u64, String> {
            match val.get(key) {
                None => Ok(0),
                Some(JsonValue::Number(n)) if *n >= 0.0 => Ok(*n as u64),
                Some(_) => Err(format!("field '{}' must be a non-negative number", key)),
            }
        }

        Ok(EvalSessionContext {
            secret_session: opt_bool(&val, "secret_session")?,
            recently_read_untrusted: opt_bool(&val, "recently_read_untrusted")?,
            deny_all: opt_bool(&val, "deny_all")?,
            approval_scope: opt_string(&val, "approval_scope")?,
            turn_counter: opt_u64(&val, "turn_counter")?,
        })
    }
}

impl EvalResponse {
    /// Serialize to JSON string.
    pub fn to_json(&self) -> String {
        let labels_json: Vec<String> = self
            .labels_applied
            .iter()
            .map(|l| {
                format!(
                    "{{\"sensitivity\":\"{}\",\"trust\":\"{}\",\"provenance\":\"{}\"}}",
                    l.sensitivity.as_str(),
                    l.trust.as_str(),
                    l.provenance.as_str()
                )
            })
            .collect();
        format!(
            "{{\"verdict\":\"{}\",\"reason\":\"{}\",\"risk_tier\":\"{}\",\"labels_applied\":[{}],\"receipt_id\":\"{}\",\"timestamp\":{}}}",
            self.verdict.as_str(),
            json_escape(&self.reason),
            self.risk_tier.as_str(),
            labels_json.join(","),
            json_escape(&self.receipt_id),
            self.timestamp
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_request_from_json() {
        let json = r#"{
            "verb": "read_ref",
            "target": ".env",
            "tool_name": "Read",
            "labels": [{"sensitivity":"secret","trust":"trusted","provenance":"user"}],
            "derived_labels": [{"sensitivity":"restricted","trust":"verified_internal","provenance":"agent"}],
            "session_secret": false,
            "session_untrusted_read": false,
            "is_posture_file": false,
            "is_sensitive_path": true,
            "is_delegation": false,
            "is_tripwire": false
        }"#;
        let req = EvalRequest::from_json(json).unwrap();
        assert_eq!(req.verb, "read_ref");
        assert_eq!(req.target, ".env");
        assert!(req.is_sensitive_path);
        assert!(!req.session_secret);
        assert_eq!(req.labels.len(), 1);
        assert_eq!(req.labels[0].sensitivity, Sensitivity::Secret);
        assert_eq!(req.derived_labels.len(), 1);
        assert_eq!(req.derived_labels[0].sensitivity, Sensitivity::Restricted);
    }

    #[test]
    fn test_eval_session_context_from_json() {
        let json = r#"{
            "secret_session": true,
            "recently_read_untrusted": false,
            "deny_all": true,
            "approval_scope": "turn",
            "turn_counter": 9
        }"#;
        let session = EvalSessionContext::from_json(json).unwrap();
        assert!(session.secret_session);
        assert!(!session.recently_read_untrusted);
        assert!(session.deny_all);
        assert_eq!(session.approval_scope, "turn");
        assert_eq!(session.turn_counter, 9);
    }

    #[test]
    fn test_eval_response_to_json() {
        let resp = EvalResponse {
            verdict: Verdict::Ask,
            reason: "sensitive file".to_string(),
            risk_tier: RiskTier::R3,
            labels_applied: vec![Label::secret()],
            receipt_id: "abc123".to_string(),
            timestamp: 1700000000,
        };
        let json = resp.to_json();
        let parsed = parse_json(&json).unwrap();
        assert_eq!(parsed.get("verdict").unwrap().as_str(), Some("ask"));
        assert_eq!(
            parsed.get("reason").unwrap().as_str(),
            Some("sensitive file")
        );
        assert_eq!(parsed.get("risk_tier").unwrap().as_str(), Some("R3"));
    }

    #[test]
    fn test_eval_request_rejects_missing_tool_name() {
        let json = r#"{
            "verb": "read_ref",
            "target": ".env"
        }"#;
        let result = EvalRequest::from_json(json);
        assert!(result.is_err(), "expected missing tool_name error");
        assert!(result.unwrap_err().contains("tool_name"));
    }

    #[test]
    fn test_eval_request_rejects_wrong_type() {
        // tool_name is a number, not a string
        let json = r#"{
            "tool_name": 42,
            "verb": "read_ref",
            "target": ".env"
        }"#;
        let result = EvalRequest::from_json(json);
        assert!(result.is_err(), "expected wrong-type error");
        let err = result.unwrap_err();
        assert!(err.contains("tool_name") && err.contains("string"));
    }

    #[test]
    fn test_eval_request_rejects_malformed_label_unknown_sensitivity() {
        // An unknown sensitivity value must reject the whole request.
        // Previously filter_map silently dropped the label, which could
        // downgrade a Secret label to the default Public.
        let json = r#"{
            "tool_name": "Read",
            "verb": "read_ref",
            "target": ".env",
            "labels": [{"sensitivity":"ULTRA_SECRET","trust":"trusted","provenance":"user"}]
        }"#;
        let result = EvalRequest::from_json(json);
        assert!(result.is_err(), "expected malformed-label rejection");
        let err = result.unwrap_err();
        assert!(
            err.contains("sensitivity") && err.contains("ULTRA_SECRET"),
            "error should name the bad field and value, got: {}",
            err
        );
    }

    #[test]
    fn test_eval_request_rejects_malformed_label_missing_trust() {
        // Label object missing a required sub-field must reject the request.
        let json = r#"{
            "tool_name": "Read",
            "verb": "read_ref",
            "target": ".env",
            "labels": [{"sensitivity":"secret","provenance":"user"}]
        }"#;
        let result = EvalRequest::from_json(json);
        assert!(result.is_err(), "expected missing-trust rejection");
        assert!(result.unwrap_err().contains("trust"));
    }

    #[test]
    fn test_eval_request_rejects_malformed_label_one_bad_entry() {
        // If the array contains a mix of valid and invalid labels, the
        // whole request must be rejected — we don't partially accept.
        let json = r#"{
            "tool_name": "Read",
            "verb": "read_ref",
            "target": ".env",
            "labels": [
                {"sensitivity":"secret","trust":"trusted","provenance":"user"},
                {"sensitivity":"public","trust":"BOGUS","provenance":"user"}
            ]
        }"#;
        let result = EvalRequest::from_json(json);
        assert!(result.is_err(), "expected bad-entry rejection");
        assert!(result.unwrap_err().contains("BOGUS"));
    }

    #[test]
    fn test_eval_request_accepts_unknown_field() {
        // Forward compat: Go may add fields the Rust core doesn't know about yet.
        let json = r#"{
            "tool_name": "Read",
            "verb": "read_ref",
            "target": ".env",
            "future_field_added_by_go": "ignored"
        }"#;
        let req = EvalRequest::from_json(json).expect("unknown fields must be ignored");
        assert_eq!(req.tool_name, "Read");
        assert_eq!(req.verb, "read_ref");
        assert_eq!(req.target, ".env");
    }

    #[test]
    fn test_eval_request_effective_labels_include_lineage() {
        let json = r#"{
            "tool_name": "Write",
            "verb": "stage_write",
            "target": "notes.md",
            "labels": [{"sensitivity":"internal","trust":"trusted","provenance":"user"}],
            "derived_labels": [{"sensitivity":"secret","trust":"verified_internal","provenance":"agent"}]
        }"#;
        let req = EvalRequest::from_json(json).unwrap();
        let labels = req.effective_labels();
        assert_eq!(labels.len(), 2);
        assert!(req.has_derived_secret());
        assert!(labels
            .iter()
            .any(|label| label.sensitivity == Sensitivity::Secret));
    }

    #[test]
    fn test_eval_request_rejects_wrong_type_labels_field() {
        let json = r#"{
            "tool_name": "Read",
            "verb": "read_ref",
            "target": ".env",
            "labels": "not-an-array"
        }"#;
        let result = EvalRequest::from_json(json);
        assert!(result.is_err(), "expected wrong-type labels rejection");
        assert!(result.unwrap_err().contains("labels"));
    }

    #[test]
    fn test_eval_request_rejects_wrong_type_derived_labels_field() {
        let json = r#"{
            "tool_name": "Write",
            "verb": "commit",
            "target": "notes.md",
            "derived_labels": "not-an-array"
        }"#;
        let result = EvalRequest::from_json(json);
        assert!(
            result.is_err(),
            "expected wrong-type derived_labels rejection"
        );
        assert!(result.unwrap_err().contains("derived_labels"));
    }
}
