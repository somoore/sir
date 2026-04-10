#!/usr/bin/env python3

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUST_EVAL = ROOT / "mister-shared" / "src" / "eval.rs"
RUST_PROTOCOL = ROOT / "mister-shared" / "src" / "protocol.rs"
GO_OUT = ROOT / "pkg" / "core" / "protocol_wire_gen.go"

STRUCT_RE = re.compile(r"pub struct (?P<name>\w+) \{(?P<body>.*?)^\}", re.MULTILINE | re.DOTALL)
FIELD_RE = re.compile(r"^\s*pub\s+(?P<name>\w+):\s+(?P<type>[^,]+),\s*$", re.MULTILINE)
MAGIC_RE = re.compile(r'pub const PROTOCOL_MAGIC:\s*&\[u8;\s*4\]\s*=\s*b"(?P<magic>[^"]+)";')
VERSION_RE = re.compile(r"pub const PROTOCOL_VERSION:\s*u8\s*=\s*(?P<version>0x[0-9A-Fa-f]+|\d+);")
MAX_FRAME_RE = re.compile(r"const MAX_FRAME_BYTES:\s*usize\s*=\s*(?P<value>[^;]+);")

REQUEST_FIELD_EXPRESSIONS = {
    "verb": "req.Intent.Verb.String()",
    "target": "req.Intent.Target",
    "tool_name": "req.ToolName",
    "labels": "nonNilLabels(req.Intent.Labels)",
    "derived_labels": "nonNilLabels(req.Intent.DerivedLabels)",
    "session_secret": "req.Session.SecretSession",
    "session_untrusted_read": "req.Session.RecentlyReadUntrusted",
    "is_posture_file": "req.Intent.IsPosture",
    "is_sensitive_path": "req.Intent.IsSensitive",
    "is_delegation": "req.Intent.IsDelegation",
    "is_tripwire": "req.Intent.IsTripwire",
}

SESSION_FIELD_EXPRESSIONS = {
    "secret_session": "req.Session.SecretSession",
    "recently_read_untrusted": "req.Session.RecentlyReadUntrusted",
    "deny_all": "req.Session.DenyAll",
    "approval_scope": "req.Session.ApprovalScope",
    "turn_counter": "uint64(req.Session.TurnCounter)",
}


def map_type(rust_type: str) -> str:
    rust_type = rust_type.strip()
    mapping = {
        "String": "string",
        "bool": "bool",
        "u64": "uint64",
        "Vec<Label>": "[]Label",
        "Verdict": "policy.Verdict",
        "RiskTier": "string",
    }
    if rust_type not in mapping:
        raise ValueError(f"unsupported Rust type in eval.rs: {rust_type}")
    return mapping[rust_type]


def snake_to_camel(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def load_structs():
    text = RUST_EVAL.read_text(encoding="utf-8")
    structs = {}
    for match in STRUCT_RE.finditer(text):
        name = match.group("name")
        if name not in {"EvalRequest", "EvalResponse", "EvalSessionContext"}:
            continue
        fields = []
        for field in FIELD_RE.finditer(match.group("body")):
            fields.append((field.group("name"), field.group("type").strip()))
        structs[name] = fields
    if "EvalRequest" not in structs or "EvalResponse" not in structs or "EvalSessionContext" not in structs:
        raise SystemExit("failed to parse EvalRequest/EvalResponse/EvalSessionContext from mister-shared/src/eval.rs")
    return structs


def load_protocol_constants():
    text = RUST_PROTOCOL.read_text(encoding="utf-8")
    magic_match = MAGIC_RE.search(text)
    version_match = VERSION_RE.search(text)
    max_frame_match = MAX_FRAME_RE.search(text)
    if not magic_match or not version_match or not max_frame_match:
        raise SystemExit("failed to parse protocol constants from mister-shared/src/protocol.rs")
    return {
        "magic": magic_match.group("magic"),
        "version": version_match.group("version"),
        "max_frame_bytes": max_frame_match.group("value").strip(),
    }


def emit_struct(go_name: str, fields):
    lines = [f"type {go_name} struct {{"]
    for rust_name, rust_type in fields:
        go_type = map_type(rust_type)
        lines.append(f'\t{snake_to_camel(rust_name)} {go_type} `json:"{rust_name}"`')
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def emit_protocol_constants(constants):
    return "\n".join(
        [
            "const (",
            f'\tprotocolMagic = "{constants["magic"]}"',
            f'\tprotocolVersion byte = {constants["version"]}',
            f'\tmaxFrameBytes uint32 = {constants["max_frame_bytes"]}',
            ")",
            "",
        ]
    )


def emit_wire_request_builder(fields):
    lines = [
        "func buildWireEvalRequest(req *Request) wireEvalRequest {",
        "\treturn wireEvalRequest{",
    ]
    for rust_name, _ in fields:
        expr = REQUEST_FIELD_EXPRESSIONS.get(rust_name)
        if expr is None:
            raise ValueError(f"missing Request mapping for EvalRequest field {rust_name!r}")
        lines.append(f"\t\t{snake_to_camel(rust_name)}: {expr},")
    lines.extend(["\t}", "}", ""])
    return "\n".join(lines)


def emit_wire_session_builder(fields):
    lines = [
        "func buildWireSessionPayload(req *Request) wireSessionPayload {",
        "\treturn wireSessionPayload{",
    ]
    for rust_name, _ in fields:
        expr = SESSION_FIELD_EXPRESSIONS.get(rust_name)
        if expr is None:
            raise ValueError(f"missing Session mapping for EvalSessionContext field {rust_name!r}")
        lines.append(f"\t\t{snake_to_camel(rust_name)}: {expr},")
    lines.extend(["\t}", "}", ""])
    return "\n".join(lines)


def emit_request_envelope():
    return "\n".join(
        [
            "type wireRequestEnvelope struct {",
            '\tRequest wireEvalRequest `json:"request"`',
            '\tSession wireSessionPayload `json:"session"`',
            '\tLease json.RawMessage `json:"lease,omitempty"`',
            "}",
            "",
        ]
    )


def emit_encode_decode_wrappers():
    return "\n".join(
        [
            "func buildWireRequestEnvelope(req *Request) wireRequestEnvelope {",
            "\tenvelope := wireRequestEnvelope{",
            "\t\tRequest: buildWireEvalRequest(req),",
            "\t\tSession: buildWireSessionPayload(req),",
            "\t}",
            "\tif len(req.LeaseJSON) > 0 && json.Valid(req.LeaseJSON) {",
            "\t\tenvelope.Lease = append(json.RawMessage(nil), req.LeaseJSON...)",
            "\t}",
            "\treturn envelope",
            "}",
            "",
            "func encodeMSTR1(req *Request) ([]byte, error) {",
            "\tpayloadJSON, err := json.Marshal(buildWireRequestEnvelope(req))",
            "\tif err != nil {",
            "\t\treturn nil, err",
            "\t}",
            "\treturn encodeFrame(payloadJSON), nil",
            "}",
            "",
            "func decodeMSTR1Response(data []byte) (*Response, error) {",
            "\tpayload, err := decodeFrame(data)",
            "\tif err != nil {",
            "\t\treturn nil, err",
            "\t}",
            "\treturn decodeWireEvalResponse(payload)",
            "}",
            "",
        ]
    )


def emit_wire_response_decoder():
    return "\n".join(
        [
            "func decodeWireEvalResponse(payload []byte) (*Response, error) {",
            "\tvar wireResp wireEvalResponse",
            "\tif err := json.Unmarshal(payload, &wireResp); err != nil {",
            "\t\treturn nil, err",
            "\t}",
            "\treturn &Response{",
            "\t\tDecision: wireResp.Verdict,",
            "\t\tReason:   wireResp.Reason,",
            "\t\tRisk:     wireResp.RiskTier,",
            "\t}, nil",
            "}",
            "",
        ]
    )


def emit_frame_codec():
    return "\n".join(
        [
            "func encodeFrame(payload []byte) []byte {",
            "\tvar buf bytes.Buffer",
            "\tbuf.WriteString(protocolMagic)",
            "\tbuf.WriteByte(protocolVersion)",
            "\tvar payloadLen [4]byte",
            "\tbinary.BigEndian.PutUint32(payloadLen[:], uint32(len(payload)))",
            "\tbuf.Write(payloadLen[:])",
            "\tbuf.Write(payload)",
            "\treturn buf.Bytes()",
            "}",
            "",
            "func decodeFrame(data []byte) ([]byte, error) {",
            "\tif len(data) < 9 {",
            '\t\treturn nil, fmt.Errorf("response too short: %d bytes", len(data))',
            "\t}",
            "\tif string(data[0:4]) != protocolMagic {",
            '\t\treturn nil, fmt.Errorf("invalid MSTR/1 magic in response")',
            "\t}",
            "\tif data[4] != protocolVersion {",
            '\t\treturn nil, fmt.Errorf("unsupported MSTR/1 version: %d", data[4])',
            "\t}",
            "\tlength := binary.BigEndian.Uint32(data[5:9])",
            "\tif length > maxFrameBytes {",
            '\t\treturn nil, fmt.Errorf("frame too large: %d bytes (max %d)", length, maxFrameBytes)',
            "\t}",
            "\tif int(length) > len(data)-9 {",
            '\t\treturn nil, fmt.Errorf("response length mismatch: declared %d, available %d", length, len(data)-9)',
            "\t}",
            "\treturn data[9 : 9+length], nil",
            "}",
            "",
        ]
    )


def main():
    structs = load_structs()
    constants = load_protocol_constants()
    body = [
        "// Code generated by scripts/generate_protocol_wire.py; DO NOT EDIT.",
        "",
        "package core",
        "",
        "import (",
        '\t"bytes"',
        '\t"encoding/binary"',
        '\t"encoding/json"',
        '\t"fmt"',
        "",
        '\t"github.com/somoore/sir/pkg/policy"',
        ")",
        "",
        emit_protocol_constants(constants),
        emit_struct("wireEvalRequest", structs["EvalRequest"]),
        emit_struct("wireEvalResponse", structs["EvalResponse"]),
        emit_struct("wireSessionPayload", structs["EvalSessionContext"]),
        emit_request_envelope(),
        emit_wire_request_builder(structs["EvalRequest"]),
        emit_wire_session_builder(structs["EvalSessionContext"]),
        emit_encode_decode_wrappers(),
        emit_wire_response_decoder(),
        emit_frame_codec(),
    ]
    GO_OUT.write_text("\n".join(body), encoding="utf-8")


if __name__ == "__main__":
    main()
