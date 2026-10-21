// Synthetic Unix-socket endpoint for the disposable Docker namespace probe.
// It has no OAuth credential and accepts exactly one lane capability.
const fs = require('node:fs');
const http = require('node:http');

const socket = '/exchange/agent.sock';
const capability = Buffer.alloc(32, 9).toString('base64url');
const complete = 'event: response.created\ndata: {"type":"response.created"}\n\nevent: response.completed\ndata: {"type":"response.completed","response":{"status":"completed"}}\n\n';

const server = http.createServer((request, response) => {
  const valid = request.method === 'POST' &&
    request.url === '/v1/responses' &&
    request.headers.authorization === `Bearer ${capability}` &&
    request.headers['x-factory-campaign-id'] === 'campaign-1' &&
    request.headers['x-factory-lane-id'] === 'lane-1';
  response.writeHead(valid ? 200 : 403, {
    'content-type': valid ? 'text/event-stream' : 'application/json',
    'content-length': valid ? Buffer.byteLength(complete) : 2,
  });
  response.end(valid ? complete : '{}');
});

server.listen(socket, () => {
  fs.chmodSync(socket, 0o660);
  console.log('fake broker ready');
});
