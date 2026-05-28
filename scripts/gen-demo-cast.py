#!/usr/bin/env python3
"""Generate assets/demo.cast (asciinema v2) from the REAL `sir demo` output.

Records `sir demo` under a pty via script(1) so colors render and all output is
captured, then replays it with realistic line timing. No hand-written content —
the recording is exactly what `sir demo` prints, so the asset never drifts from
the tool.

Usage:  python3 scripts/gen-demo-cast.py [path-to-sir]   (default: ./bin/sir)
"""
import json
import os
import subprocess
import sys
import tempfile
import time

SIR = sys.argv[1] if len(sys.argv) > 1 else "./bin/sir"
OUT = "assets/demo.cast"

env = dict(os.environ)
env.pop("NO_COLOR", None)
env["TERM"] = "xterm-256color"

ts = tempfile.NamedTemporaryFile(prefix="sir-demo-", suffix=".typescript", delete=False).name
# util-linux: -q quiet, -e return child's exit code, -c command, last arg = file
subprocess.run(["script", "-qec", f"{SIR} demo", ts], env=env, check=False)
with open(ts, "rb") as f:
    raw = f.read().decode("utf-8", "replace")
os.unlink(ts)

# Drop script(1)'s own banner lines.
lines = [
    ln for ln in raw.splitlines(keepends=True)
    if not ln.startswith("Script started on") and not ln.startswith("Script done on")
]

header = {
    "version": 2,
    "width": 100,
    "height": 46,
    "timestamp": int(time.time()),
    "title": "sir demo — read .env, then blocked egress",
    "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
}

events = [[0.4, "o", "$ sir demo\r\n"]]
t = 0.7
for line in lines:
    line = line.replace("\r\n", "\n").replace("\n", "\r\n")
    t += 0.20 if line.strip().startswith("---") else 0.05
    events.append([round(t, 3), "o", line])
events.append([round(t + 1.2, 3), "o", "$ \r\n"])

with open(OUT, "w") as f:
    f.write(json.dumps(header) + "\n")
    for ev in events:
        f.write(json.dumps(ev) + "\n")

print(f"wrote {OUT}: {len(events)} events from {len(lines)} real output lines")
