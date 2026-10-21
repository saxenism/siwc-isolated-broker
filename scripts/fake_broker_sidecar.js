// Synthetic Unix-socket endpoint for the disposable Docker namespace probe.
// It has no OAuth credential and accepts exactly one lane capability.
const fs = require('node:fs');
const http = require('node:http');

const socket = '/exchange/agent.sock';
const capability = Buffer.alloc(32, 9).toString('base64url');
const text = 'synthetic packaged bridge works';
const message = {
  id: 'msg_bridge_001', type: 'message', status: 'completed', role: 'assistant',
  content: [{type: 'output_text', text, annotations: []}],
};
const base = {
  id: 'resp_bridge_001', object: 'response', created_at: 1_800_000_000,
  completed_at: 1_800_000_001, error: null, incomplete_details: null,
  instructions: null, model: 'gpt-6-sol', output: [message],
  parallel_tool_calls: false, previous_response_id: null,
  reasoning: {effort: null, summary: null}, store: false,
  text: {format: {type: 'text'}}, tool_choice: 'auto', tools: [],
  truncation: 'disabled',
  usage: {input_tokens: 1, output_tokens: 4, total_tokens: 5},
};
const events = [
  ['response.created', {response: {...base, status: 'in_progress', completed_at: null, output: []}}],
  ['response.output_item.added', {output_index: 0, item: {...message, status: 'in_progress', content: []}}],
  ['response.content_part.added', {item_id: message.id, output_index: 0, content_index: 0,
    part: {type: 'output_text', text: '', annotations: []}}],
  ['response.output_text.delta', {item_id: message.id, output_index: 0, content_index: 0, delta: text}],
  ['response.content_part.done', {item_id: message.id, output_index: 0, content_index: 0,
    part: message.content[0]}],
  ['response.output_item.done', {output_index: 0, item: message}],
  ['response.completed', {response: {...base, status: 'completed'}}],
];
const complete = events.map(([type, fields], sequence_number) =>
  `event: ${type}\ndata: ${JSON.stringify({type, sequence_number, ...fields})}\n\n`
).join('');

const server = http.createServer((request, response) => {
  const validRoute = request.method === 'POST' &&
    request.url === '/v1/responses' &&
    request.headers.authorization === `Bearer ${capability}` &&
    request.headers['x-factory-campaign-id'] === 'campaign-1' &&
    request.headers['x-factory-lane-id'] === 'lane-1';
  const chunks = [];
  request.on('data', chunk => chunks.push(chunk));
  request.on('end', () => {
    let validBody = false;
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString());
      validBody = body.store === false && body.stream === true && Array.isArray(body.input);
    } catch {}
    const valid = validRoute && validBody;
    if (!valid) {
      console.error('fixture rejected request', JSON.stringify({
        method: request.method, path: request.url,
        auth_match: request.headers.authorization === `Bearer ${capability}`,
        campaign_match: request.headers['x-factory-campaign-id'] === 'campaign-1',
        lane_match: request.headers['x-factory-lane-id'] === 'lane-1',
        shape_match: validBody,
      }));
    }
    response.writeHead(valid ? 200 : 403, {
      'content-type': valid ? 'text/event-stream' : 'application/json',
      'content-length': valid ? Buffer.byteLength(complete) : 2,
    });
    response.end(valid ? complete : '{}');
  });
});

server.listen(socket, () => {
  fs.chmodSync(socket, 0o660);
  console.log('fake broker ready');
});
