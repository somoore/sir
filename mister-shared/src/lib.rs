//! mister-shared: Shared types for MSTR/1 protocol between mister-core and the Go bridge.
//!
//! ZERO external dependencies. All serialization is hand-rolled.

mod eval;
mod json;
mod labels;
mod policy_surface;
mod protocol;
mod sha256;
mod time;
mod verb;

pub use eval::{EvalRequest, EvalResponse, EvalSessionContext, LeaseResource, Sink};
pub use json::{parse_json, JsonValue};
pub use labels::{Label, Provenance, RiskTier, Sensitivity, TrustLevel, Verdict};
pub use policy_surface::{ApprovalScope, PostureState, SESSION_SCHEMA_VERSION};
pub use protocol::{decode_frame, encode_frame, write_frame, PROTOCOL_MAGIC, PROTOCOL_VERSION};
pub use sha256::{hex_encode, sha256, sha256_hex};
pub use time::{now_epoch_millis, now_epoch_secs};
pub use verb::Verb;
