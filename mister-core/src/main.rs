//! mister-core: MSTR/1 stdin/stdout interface.
//!
//! Single invocation per evaluation (no daemon).
//! Reads a binary-encoded MSTR/1 request from stdin,
//! evaluates it against the policy oracle,
//! writes a binary-encoded MSTR/1 response to stdout.
//!
//! MSTR/1 frame format:
//!   magic(4): "MSTR"
//!   version(1): 0x01
//!   payload_len(4): big-endian u32
//!   payload(N): JSON-encoded request or response

use std::io::{self, BufWriter};

use mister_core::controller;
use mister_core::lease::Lease;
use mister_core::session::SessionState;
use mister_shared::{decode_frame, parse_json, write_frame, EvalRequest, EvalSessionContext};

fn main() {
    let result = run();
    if let Err(e) = result {
        eprintln!("mister-core error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    // Read the MSTR/1 frame from stdin.
    let payload = decode_frame(&mut stdin).map_err(|e| format!("failed to read frame: {}", e))?;
    let payload_str =
        String::from_utf8(payload).map_err(|e| format!("invalid UTF-8 payload: {}", e))?;

    // Parse the top-level JSON which contains the request, lease, and session.
    let top = parse_json(&payload_str).map_err(|e| format!("failed to parse JSON: {}", e))?;

    // Parse the eval request.
    let req_val = top
        .get("request")
        .ok_or_else(|| "missing 'request' field".to_string())?;
    let req_json = req_val.to_json_string();
    let req = EvalRequest::from_json(&req_json).map_err(|e| format!("bad request: {}", e))?;

    // Parse the lease (optional -- use default if not provided).
    let lease = if let Some(lease_val) = top.get("lease") {
        let lease_json = lease_val.to_json_string();
        Lease::from_json(&lease_json).map_err(|e| format!("bad lease: {}", e))?
    } else {
        Lease::default_lease()
    };

    // Parse session state.
    let session = if let Some(session_val) = top.get("session") {
        let session_json = session_val.to_json_string();
        let wire_session = EvalSessionContext::from_json(&session_json)
            .map_err(|e| format!("bad session: {}", e))?;
        let mut s = SessionState::new();
        if wire_session.secret_session {
            s.mark_secret();
        }
        if wire_session.recently_read_untrusted {
            s.mark_untrusted_read();
        }
        if wire_session.deny_all {
            s.mark_deny_all();
        }
        if !wire_session.approval_scope.is_empty() {
            s.set_approval_scope(&wire_session.approval_scope);
        }
        if wire_session.turn_counter > 0 {
            s.advance_turn(wire_session.turn_counter);
        }
        s
    } else {
        SessionState::new()
    };

    // Evaluate.
    let response = controller::evaluate(&req, &lease, &session);

    // Write the MSTR/1 response frame to stdout.
    let response_json = response.to_json();
    let stdout = io::stdout();
    let mut stdout = BufWriter::new(stdout.lock());
    write_frame(&mut stdout, response_json.as_bytes())
        .map_err(|e| format!("failed to write frame: {}", e))?;

    Ok(())
}
