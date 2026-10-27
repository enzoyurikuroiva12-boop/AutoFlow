import test from 'node:test';
import assert from 'node:assert/strict';
import { createDatabase } from '../server/db.mjs';
import { assertPublicHost, runFlow, validateFlow } from '../server/engine.mjs';
import { protectDefinition, runtimeDefinition, viewDefinition } from '../server/secrets.mjs';

function makeGraph() {
  return {
    nodes: [
      { id: 'trigger', type: 'manualTrigger', position: { x: 0, y: 0 }, data: { label: 'Start', config: {} } },
      { id: 'check', type: 'condition', position: { x: 1, y: 0 }, data: { label: 'Check', config: { field: 'trigger.body.approved', operator: 'equals', value: 'true' } } },
      { id: 'yes', type: 'internalLog', position: { x: 2, y: 0 }, data: { label: 'Yes', config: { message: 'approved' } } },
      { id: 'no', type: 'internalLog', position: { x: 2, y: 1 }, data: { label: 'No', config: { message: 'rejected' } } },
    ],
    edges: [
      { id: 'a', source: 'trigger', target: 'check' },
      { id: 'b', source: 'check', sourceHandle: 'true', target: 'yes' },
      { id: 'c', source: 'check', sourceHandle: 'false', target: 'no' },
    ],
  };
}

test('validates a condition graph and rejects cycles and disconnected blocks', () => {
  const graph = makeGraph();
  assert.deepEqual(validateFlow(graph), []);
  assert.ok(validateFlow({ ...graph, edges: [...graph.edges, { id: 'cycle', source: 'yes', target: 'trigger' }] }).some((e) => e.includes('ciclo')));
  assert.ok(validateFlow({ ...graph, edges: graph.edges.filter((edge) => edge.target !== 'no') }).some((e) => e.includes('saídas')));
  assert.ok(validateFlow({ ...graph, nodes: [...graph.nodes, { id: 'orphan', type: 'internalLog', position: { x: 0, y: 0 }, data: { label: 'Orphan', config: {} } }] }).some((e) => e.includes('sem caminho')));
});

test('runs the true condition branch on the server and persists step outcomes', async () => {
  const db = createDatabase({ DB_PATH: ':memory:' });
  await db.migrate();
  const workspace = 'workspace-test'; const automation = 'automation-test'; const now = new Date().toISOString();
  await db.run('INSERT INTO workspaces (id, name, plan, created_at) VALUES (?, ?, ?, ?)', workspace, 'Test', 'free', now);
  await db.run('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)', 'user-test', 'test@example.com', 'Test', 'hash', now);
  await db.run('INSERT INTO automations (id, workspace_id, name, description, active, version, definition, created_at, updated_at) VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?)', automation, workspace, 'Condition flow', '', JSON.stringify(makeGraph()), now, now);
  const result = await runFlow(db, workspace, { id: automation, definition: JSON.stringify(makeGraph()) }, { body: { approved: true } }, { idempotencyKey: 'test-run-1' });
  assert.equal(result.status, 'completed');
  assert.deepEqual(result.steps.map((step) => step.nodeId), ['trigger', 'check', 'yes']);
  assert.equal(result.steps[1].branch, 'true');
  const stored = await db.get('SELECT status, steps_json FROM executions WHERE id = ?', result.id);
  assert.equal(stored.status, 'completed');
  assert.equal(JSON.parse(stored.steps_json).length, 3);
  await db.close();
});

test('records an SSRF-blocked HTTP action as a failed server execution', async () => {
  const db = createDatabase({ DB_PATH: ':memory:' });
  await db.migrate();
  const now = new Date().toISOString();
  await db.run('INSERT INTO workspaces (id, name, plan, created_at) VALUES (?, ?, ?, ?)', 'workspace-ssrf', 'Test', 'free', now);
  await db.run('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)', 'user-ssrf', 'ssrf@example.com', 'Test', 'hash', now);
  const definition = { nodes: [
    { id: 'trigger', type: 'manualTrigger', position: { x: 0, y: 0 }, data: { label: 'Start', config: {} } },
    { id: 'http', type: 'httpRequest', position: { x: 1, y: 0 }, data: { label: 'Private address', config: { method: 'GET', url: 'http://127.0.0.1:8080' } } },
  ], edges: [{ id: 'edge', source: 'trigger', target: 'http' }] };
  await db.run('INSERT INTO automations (id, workspace_id, name, description, active, version, definition, created_at, updated_at) VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?)', 'automation-ssrf', 'workspace-ssrf', 'Blocked request', '', JSON.stringify(definition), now, now);
  await assert.rejects(runFlow(db, 'workspace-ssrf', { id: 'automation-ssrf', definition: JSON.stringify(definition) }, {}), /não é permitido/);
  const execution = await db.get('SELECT status, steps_json FROM executions WHERE workspace_id = ?', 'workspace-ssrf');
  assert.equal(execution.status, 'failed');
  assert.equal(JSON.parse(execution.steps_json).at(-1).status, 'failed');
  await db.close();
});

test('blocks loopback and private network destinations', async () => {
  await assert.rejects(assertPublicHost('127.0.0.1'), /não é permitido/);
  await assert.rejects(assertPublicHost('10.20.30.40'), /não é permitido/);
  await assert.rejects(assertPublicHost('169.254.169.254'), /não é permitido/);
  await assert.rejects(assertPublicHost('::1'), /não é permitido/);
  await assert.rejects(assertPublicHost('::ffff:7f00:1'), /não é permitido/);
  await assert.rejects(assertPublicHost('localhost'), /não é permitido/);
});

test('encrypts Discord webhook credentials and returns only a mask to the editor', () => {
  process.env.AUTOFLOW_CREDENTIALS_KEY = 'test-only-encryption-key';
  const webhookUrl = 'https://discord.com/api/webhooks/111111/secret-token';
  const definition = { nodes: [{ id: 'discord', type: 'discord', data: { label: 'Discord', config: { webhookUrl } } }], edges: [] };
  const stored = protectDefinition(definition);
  assert.notEqual(stored.nodes[0].data.config.webhookUrl, webhookUrl);
  assert.equal(viewDefinition(stored).nodes[0].data.config.webhookUrl, '••••••••');
  assert.equal(runtimeDefinition(stored).nodes[0].data.config.webhookUrl, webhookUrl);
  const reSaved = protectDefinition(viewDefinition(stored), stored);
  assert.equal(runtimeDefinition(reSaved).nodes[0].data.config.webhookUrl, webhookUrl);
  delete process.env.AUTOFLOW_CREDENTIALS_KEY;
});
