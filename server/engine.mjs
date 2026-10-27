import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { randomUUID } from 'node:crypto';
import { redact, runtimeDefinition } from './secrets.mjs';

const nodeTypes = new Set(['manualTrigger', 'httpRequest', 'discord', 'condition', 'internalLog']);
const ops = new Set(['equals', 'notEquals', 'contains', 'greaterThan', 'lessThan', 'exists']);
const MAX_RESPONSE = 1024 * 1024;
const MAX_EXECUTION_MS = 60_000;
const MAX_EXECUTION_LOG = 2 * 1024 * 1024;

export function validateFlow(definition) {
  const errors = [];
  const nodes = Array.isArray(definition?.nodes) ? definition.nodes : [];
  const edges = Array.isArray(definition?.edges) ? definition.edges : [];
  if (!nodes.length) return ['Adicione um gatilho e pelo menos uma etapa.'];
  if (nodes.length > 50) errors.push('O fluxo pode ter no máximo 50 blocos.');
  if (edges.length > 100) errors.push('O fluxo pode ter no máximo 100 conexões.');
  const ids = new Set();
  for (const n of nodes) {
    if (!n.id || ids.has(n.id)) errors.push('Cada bloco precisa ter um identificador único.');
    ids.add(n.id);
    if (!nodeTypes.has(n.type)) errors.push(`O bloco “${n.type || 'desconhecido'}” não é compatível.`);
  }
  const triggers = nodes.filter((n) => n.type === 'manualTrigger');
  if (triggers.length !== 1) errors.push('O fluxo precisa ter exatamente um gatilho manual.');
  for (const edge of edges) {
    if (!ids.has(edge.source) || !ids.has(edge.target)) errors.push('Há uma conexão ligada a um bloco inexistente.');
    if (edge.source === edge.target) errors.push('Um bloco não pode apontar para si mesmo.');
  }

  for (const node of nodes) {
    const config = node.data?.config || {};
    if (node.type === 'httpRequest') {
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(String(config.method || 'GET').toUpperCase())) errors.push(`Escolha um método HTTP válido no bloco “${node.data?.label || node.id}”.`);
      if (!String(config.url || '').trim()) errors.push(`Informe a URL do bloco “${node.data?.label || node.id}”.`);
    }
    if (node.type === 'discord' && !String(config.webhookUrl || '').trim()) errors.push(`Informe o webhook do Discord no bloco “${node.data?.label || node.id}”.`);
    if (node.type === 'condition') {
      if (!String(config.field || '').trim()) errors.push(`Informe o campo da condição no bloco “${node.data?.label || node.id}”.`);
      if (!ops.has(config.operator)) errors.push(`Escolha um operador válido no bloco “${node.data?.label || node.id}”.`);
      const outgoing = edges.filter((edge) => edge.source === node.id);
      if (!outgoing.some((edge) => edge.sourceHandle === 'true') || !outgoing.some((edge) => edge.sourceHandle === 'false')) errors.push(`Conecte as saídas “Verdadeiro” e “Falso” do bloco “${node.data?.label || node.id}”.`);
    }
  }
  const graph = new Map(nodes.map((n) => [n.id, []]));
  for (const edge of edges) if (graph.has(edge.source) && graph.has(edge.target)) graph.get(edge.source).push(edge.target);
  const indegree = new Map(nodes.map((n) => [n.id, 0]));
  for (const edge of edges) if (indegree.has(edge.target)) indegree.set(edge.target, indegree.get(edge.target) + 1);
  const queue = nodes.filter((n) => indegree.get(n.id) === 0).map((n) => n.id);
  const order = [];
  while (queue.length) {
    const id = queue.shift();
    order.push(id);
    for (const next of graph.get(id) || []) {
      indegree.set(next, indegree.get(next) - 1);
      if (indegree.get(next) === 0) queue.push(next);
    }
  }
  if (order.length !== nodes.length) errors.push('O fluxo contém um ciclo. Remova uma conexão para continuar.');
  if (triggers.length === 1) {
    const reachable = new Set([triggers[0].id]);
    const queueReach = [triggers[0].id];
    while (queueReach.length) for (const next of graph.get(queueReach.shift()) || []) if (!reachable.has(next)) { reachable.add(next); queueReach.push(next); }
    if (reachable.size !== nodes.length) errors.push('Conecte todos os blocos ao gatilho. Há etapas sem caminho de entrada.');
  }
  return [...new Set(errors)];
}

function ipv4Private(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => part < 0 || part > 255)) return true;
  const [a, b, c] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && c === 0) || (b === 0 && c === 2))) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0 && c === 113);
}

function ipv6Private(ip) {
  const value = ip.toLowerCase().split('%')[0];
  if (value.includes('.')) {
    const last = value.slice(value.lastIndexOf(':') + 1);
    if (isIP(last) === 4 && ipv4Private(last)) return true;
  }
  if (value.startsWith('::ffff:')) {
    const hex = value.slice(7).split(':');
    if (hex.length === 2 && hex.every((part) => /^[\da-f]{1,4}$/.test(part))) {
      const number = (Number.parseInt(hex[0], 16) * 0x10000 + Number.parseInt(hex[1], 16)) >>> 0;
      const mapped = `${number >>> 24}.${number >>> 16 & 255}.${number >>> 8 & 255}.${number & 255}`;
      if (ipv4Private(mapped)) return true;
    }
  }
  return value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') || /^fe[89ab]/.test(value) || value.startsWith('ff') || value.startsWith('64:ff9b:') || value.startsWith('2001:db8:') || value.startsWith('2001:0:') || value.startsWith('2001:10:') || value.startsWith('2001:20:') || value.startsWith('2002:');
}

export async function assertPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('O destino da requisição não é permitido.');
  const literalFamily = isIP(host);
  let addresses;
  if (literalFamily) addresses = [{ address: host, family: literalFamily }];
  else {
    let timer;
    try {
      addresses = await Promise.race([
        lookup(host, { all: true, verbatim: true }),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('A resolução do destino excedeu o limite de tempo.')), 3000); }),
      ]);
    } finally { clearTimeout(timer); }
  }
  if (!addresses.length || addresses.some(({ address, family }) => family === 4 ? ipv4Private(address) : ipv6Private(address))) throw new Error('O destino da requisição não é permitido.');
  return addresses[0];
}

async function safeRequest(urlText, { method = 'GET', headers = {}, body = null, discord = false } = {}) {
  let url = new URL(urlText);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('Use uma URL HTTP ou HTTPS válida.');
  for (let redirect = 0; redirect <= 3; redirect++) {
    if (url.username || url.password) throw new Error('Credenciais embutidas na URL não são permitidas.');
    if (discord && (url.protocol !== 'https:' || !['discord.com', 'discordapp.com'].includes(url.hostname.toLowerCase()))) throw new Error('Use uma URL oficial de webhook do Discord.');
    const target = await assertPublicHost(url.hostname);
    const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const response = await new Promise((resolve, reject) => {
      const request = transport({
        protocol: url.protocol,
        hostname: url.hostname.replace(/^\[|\]$/g, ''),
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        method,
        path: `${url.pathname}${url.search}`,
        headers: { 'user-agent': 'AutoFlow/0.1', ...headers, ...(body ? { 'content-length': Buffer.byteLength(body) } : {}) },
        servername: isIP(url.hostname.replace(/^\[|\]$/g, '')) ? undefined : url.hostname,
        lookup: (_hostname, _options, callback) => callback(null, target.address, target.family),
        timeout: 10000,
        maxHeaderSize: 16 * 1024,
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_RESPONSE) { request.destroy(new Error('A resposta excede o limite de 1 MB.')); return; }
          chunks.push(chunk);
        });
        res.on('end', () => resolve({ status: res.statusCode || 0, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
      });
      request.on('timeout', () => request.destroy(new Error('A requisição excedeu o limite de 10 segundos.')));
      request.on('error', reject);
      if (body) request.write(body);
      request.end();
    });
    if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.location) {
      if (redirect === 3) throw new Error('A requisição excedeu o limite de redirecionamentos.');
      const nextUrl = new URL(response.headers.location, url);
      if (nextUrl.origin !== url.origin) {
        headers = Object.fromEntries(Object.entries(headers).filter(([name]) => !/^(authorization|proxy-authorization|cookie)$/i.test(name)));
      }
      url = nextUrl;
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) { method = 'GET'; body = null; }
      continue;
    }
    let data = response.text;
    try { data = response.text ? JSON.parse(response.text) : null; } catch {}
    return { status: response.status, body: redact(data) };
  }
  throw new Error('Não foi possível concluir a requisição.');
}

function pathValue(root, path) {
  return String(path || '').split('.').reduce((value, part) => value == null ? undefined : value[part], root);
}

function substitute(value, context) {
  if (typeof value === 'string') return value.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_match, path) => {
    const found = pathValue(context, path.trim());
    return found === undefined ? '' : typeof found === 'object' ? JSON.stringify(found) : String(found);
  });
  if (Array.isArray(value)) return value.map((item) => substitute(item, context));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, substitute(item, context)]));
  return value;
}

function condition(value, config) {
  const expected = config.value;
  switch (config.operator) {
    case 'equals': return String(value) === String(expected);
    case 'notEquals': return String(value) !== String(expected);
    case 'contains': return Array.isArray(value) ? value.includes(expected) : String(value ?? '').includes(String(expected ?? ''));
    case 'greaterThan': return Number(value) > Number(expected);
    case 'lessThan': return Number(value) < Number(expected);
    case 'exists': return value !== undefined && value !== null && value !== '';
    default: return false;
  }
}

function parseHeaders(value) {
  if (!value) return {};
  const headers = typeof value === 'string' ? JSON.parse(value) : value;
  if (!headers || Array.isArray(headers) || typeof headers !== 'object') throw new Error('Os cabeçalhos precisam ser um objeto JSON.');
  const out = {};
  for (const [key, val] of Object.entries(headers)) {
    if (/^(host|content-length|connection|transfer-encoding)$/i.test(key)) throw new Error(`O cabeçalho “${key}” não pode ser alterado.`);
    out[key] = String(val);
  }
  return out;
}

export async function runFlow(db, workspaceId, automation, input = {}, { idempotencyKey = null } = {}) {
  const definition = runtimeDefinition(JSON.parse(automation.definition));
  const errors = validateFlow(definition);
  if (errors.length) throw Object.assign(new Error(errors.join(' ')), { statusCode: 400, validation: errors });
  const nodeById = new Map(definition.nodes.map((node) => [node.id, node]));
  const edges = definition.edges;
  const executionId = randomUUID();
  const startedAt = new Date().toISOString();
  await db.run('INSERT INTO executions (id, workspace_id, automation_id, idempotency_key, trigger_type, status, input_json, started_at, steps_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', executionId, workspaceId, automation.id, idempotencyKey, 'manual', 'pending', JSON.stringify(redact(input)), startedAt, '[]');
  await db.run("UPDATE executions SET status = 'running' WHERE id = ? AND workspace_id = ?", executionId, workspaceId);
  const steps = [];
  const results = {};
  const enabled = new Set([definition.nodes.find((node) => node.type === 'manualTrigger').id]);
  const indegree = new Map(definition.nodes.map((node) => [node.id, 0]));
  for (const edge of edges) indegree.set(edge.target, indegree.get(edge.target) + 1);
  const q = definition.nodes.filter((node) => indegree.get(node.id) === 0).map((node) => node.id);
  const order = [];
  while (q.length) { const id = q.shift(); order.push(id); for (const edge of edges.filter((item) => item.source === id)) { indegree.set(edge.target, indegree.get(edge.target) - 1); if (indegree.get(edge.target) === 0) q.push(edge.target); } }
  const context = { trigger: input, steps: results };
  try {
    for (const nodeId of order) {
      const node = nodeById.get(nodeId);
      if (!enabled.has(nodeId)) continue;
      if (Date.now() - Date.parse(startedAt) > MAX_EXECUTION_MS) throw new Error('A execução excedeu o limite de 60 segundos.');
      const started = Date.now();
      let output;
      let branch;
      const config = substitute(node.data?.config || {}, context);
      if (node.type === 'manualTrigger') output = input;
      else if (node.type === 'internalLog') output = { recorded: true, message: config.message || 'Etapa registrada.' };
      else if (node.type === 'httpRequest') {
        const method = String(config.method || 'GET').toUpperCase();
        const body = method === 'GET' || method === 'DELETE' || !config.body ? null : (typeof config.body === 'string' ? config.body : JSON.stringify(config.body));
        const result = await safeRequest(config.url, { method, headers: parseHeaders(config.headers), body });
        output = result;
        if (result.status < 200 || result.status >= 300) throw new Error(`A requisição HTTP respondeu com status ${result.status}.`);
      } else if (node.type === 'discord') {
        const result = await safeRequest(config.webhookUrl, { method: 'POST', discord: true, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ content: config.message || 'Nova execução do AutoFlow.' }) });
        output = { status: result.status, sent: result.status >= 200 && result.status < 300 };
        if (!output.sent) throw new Error(`O Discord respondeu com status ${result.status}.`);
      } else if (node.type === 'condition') {
        const value = pathValue(context, config.field);
        branch = condition(value, config) ? 'true' : 'false';
        output = { field: config.field, value: redact(value), branch };
      }
      const step = { nodeId, type: node.type, label: node.data?.label || node.type, status: 'completed', startedAt: new Date(started).toISOString(), finishedAt: new Date().toISOString(), durationMs: Date.now() - started, output: redact(output), ...(branch ? { branch } : {}) };
      steps.push(step);
      if (Buffer.byteLength(JSON.stringify(steps)) > MAX_EXECUTION_LOG) {
        step.status = 'failed';
        step.output = { truncated: true };
        step.error = 'O histórico desta execução excedeu o limite de 2 MB.';
        throw new Error(step.error);
      }
      results[nodeId] = output;
      context.steps[nodeId] = output;
      for (const edge of edges.filter((item) => item.source === nodeId)) if (!branch || edge.sourceHandle === branch) enabled.add(edge.target);
      await db.run('UPDATE executions SET steps_json = ? WHERE id = ? AND workspace_id = ?', JSON.stringify(steps), executionId, workspaceId);
    }
    const finishedAt = new Date().toISOString();
    await db.run("UPDATE executions SET status = 'completed', steps_json = ?, finished_at = ?, duration_ms = ? WHERE id = ? AND workspace_id = ?", JSON.stringify(steps), finishedAt, Date.now() - Date.parse(startedAt), executionId, workspaceId);
    return { id: executionId, status: 'completed', steps, startedAt, finishedAt, durationMs: Date.now() - Date.parse(startedAt) };
  } catch (error) {
    const finishedAt = new Date().toISOString();
    const current = steps.length;
    const failingNode = steps.at(-1)?.status === 'failed' ? null : order.find((id) => enabled.has(id) && !steps.some((step) => step.nodeId === id));
    if (failingNode) steps.push({ nodeId: failingNode, type: nodeById.get(failingNode)?.type, label: nodeById.get(failingNode)?.data?.label, status: 'failed', startedAt: finishedAt, finishedAt, durationMs: 0, error: redact(error.message || 'Falha na etapa.') });
    await db.run("UPDATE executions SET status = 'failed', steps_json = ?, error_message = ?, finished_at = ?, duration_ms = ? WHERE id = ? AND workspace_id = ?", JSON.stringify(steps), redact(error.message || 'Falha na execução.'), finishedAt, Date.now() - Date.parse(startedAt), executionId, workspaceId);
    error.executionId = executionId;
    error.completedSteps = current;
    throw error;
  }
}
