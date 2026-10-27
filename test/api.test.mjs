import test from 'node:test';
import assert from 'node:assert/strict';

process.env.DB_PATH = ':memory:';
process.env.AUTOFLOW_NO_LISTEN = 'true';
const { db, route } = await import('../server/index.mjs');

function makeRequest(method, url, { cookie, body, origin = 'http://localhost:5173', headers = {} } = {}) {
  const encoded = body === undefined ? null : Buffer.from(JSON.stringify(body));
  return {
    method,
    url,
    headers: { host: 'localhost:3001', ...(cookie ? { cookie } : {}), ...(encoded ? { 'content-type': 'application/json', origin } : {}), ...headers },
    socket: { remoteAddress: '127.0.0.1' },
    async *[Symbol.asyncIterator]() { if (encoded) yield encoded; },
  };
}

async function call(method, url, options) {
  const response = { statusCode: 0, headers: {}, body: '', headersSent: false, writeHead(status, headers = {}) { this.statusCode = status; Object.assign(this.headers, headers); this.headersSent = true; }, setHeader(name, value) { this.headers[name.toLowerCase()] = value; }, end(body = '') { this.body = body; }, destroy() {} };
  try { await route(makeRequest(method, url, options), response); }
  catch (error) { response.writeHead(error.statusCode || 500, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: error.message })); }
  return { ...response, json: JSON.parse(response.body || '{}') };
}

function session(response) { return response.headers['set-cookie'].match(/autoflow_session=([^;]+)/)[1]; }
function account(email) { return { name: 'AutoFlow User', email, password: 'A-strong-passphrase-55' }; }

test('registers, authenticates and isolates automations by workspace', async () => {
  const first = await call('POST', '/api/auth/register', { body: account('first@example.com') });
  assert.equal(first.statusCode, 201);
  assert.equal(first.json.user.workspace.plan, 'free');
  const firstCookie = session(first);
  assert.equal((await call('GET', '/api/auth/session', { cookie: `autoflow_session=${firstCookie}` })).json.user.email, 'first@example.com');

  const flow = { nodes: [
    { id: 'trigger', type: 'manualTrigger', position: { x: 0, y: 0 }, data: { label: 'Start', config: {} } },
    { id: 'log', type: 'internalLog', position: { x: 1, y: 0 }, data: { label: 'Log', config: { message: 'Ready' } } },
  ], edges: [{ id: 'edge', source: 'trigger', target: 'log' }] };
  const created = await call('POST', '/api/automations', { cookie: `autoflow_session=${firstCookie}`, body: { name: 'Private flow', definition: flow } });
  assert.equal(created.statusCode, 201);
  const ids = [created.json.automation.id];
  for (let index = 2; index <= 4; index += 1) {
    const draft = await call('POST', '/api/automations', { cookie: `autoflow_session=${firstCookie}`, body: { name: `Draft ${index}`, definition: flow } });
    assert.equal(draft.statusCode, 201);
    ids.push(draft.json.automation.id);
  }
  for (const id of ids.slice(0, 3)) assert.equal((await call('POST', `/api/automations/${id}/toggle`, { cookie: `autoflow_session=${firstCookie}`, body: { active: true } })).statusCode, 200);
  assert.equal((await call('POST', `/api/automations/${ids[3]}/toggle`, { cookie: `autoflow_session=${firstCookie}`, body: { active: true } })).statusCode, 403);
  const idempotency = { cookie: `autoflow_session=${firstCookie}`, headers: { 'idempotency-key': 'one-request-one-run' }, body: { input: {} } };
  const firstRun = await call('POST', `/api/automations/${created.json.automation.id}/run`, idempotency);
  const retriedRun = await call('POST', `/api/automations/${created.json.automation.id}/run`, idempotency);
  assert.equal(firstRun.json.execution.id, retriedRun.json.execution.id);
  const now = new Date().toISOString();
  const workspaceId = (await db.get('SELECT workspace_id FROM automations WHERE id = ?', created.json.automation.id)).workspace_id;
  for (let index = 0; index < 499; index += 1) {
    await db.run('INSERT INTO executions (id, workspace_id, automation_id, trigger_type, status, input_json, steps_json, started_at, finished_at, duration_ms, attempt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)', `quota-${index}`, workspaceId, created.json.automation.id, 'manual', 'completed', '{}', '[]', now, now, 1);
  }
  assert.equal((await call('POST', `/api/automations/${created.json.automation.id}/run`, { cookie: `autoflow_session=${firstCookie}`, body: { input: {} } })).statusCode, 403);

  const second = await call('POST', '/api/auth/register', { body: account('second@example.com') });
  const secondCookie = session(second);
  const inaccessible = await call('GET', `/api/automations/${created.json.automation.id}`, { cookie: `autoflow_session=${secondCookie}` });
  assert.equal(inaccessible.statusCode, 404);

  const login = await call('POST', '/api/auth/login', { body: { email: 'first@example.com', password: 'A-strong-passphrase-55' } });
  assert.equal(login.statusCode, 200);
  assert.equal(login.json.user.email, 'first@example.com');
  const badLogin = await call('POST', '/api/auth/login', { body: { email: 'first@example.com', password: 'wrong-password' } });
  assert.equal(badLogin.statusCode, 401);
});

test('requires a session for workspace data and rejects a foreign request origin', async () => {
  const anonymous = await call('GET', '/api/automations');
  assert.equal(anonymous.statusCode, 401);
  const csrf = await call('POST', '/api/auth/login', { body: { email: 'first@example.com', password: 'A-strong-passphrase-55' }, origin: 'https://attacker.example' });
  assert.equal(csrf.statusCode, 403);
});

test.after(async () => { await db.close(); });
