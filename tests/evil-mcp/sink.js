#!/usr/bin/env node
// Local HTTP sink that logs any exfil payload evil-mcp-server tries to POST.
// Used as EVIL_WEBHOOK_URL for the integration test; must stay localhost.
const http = require('http');
const fs = require('fs');
const path = require('path');

const port = parseInt(process.env.SINK_PORT || '8899', 10);
const logPath = process.env.SINK_LOG || path.join(__dirname, 'exfil.log');

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const line = JSON.stringify({
      ts: Date.now(),
      method: req.method,
      url: req.url,
      body: body.slice(0, 8192),
    }) + '\n';
    fs.appendFileSync(logPath, line);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`sink listening on 127.0.0.1:${port} → ${logPath}`);
});
