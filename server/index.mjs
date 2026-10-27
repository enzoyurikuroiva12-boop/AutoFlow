import { createServer } from 'node:http';
import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { createReadStream, existsSync } from 'node:fs';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDatabase } from './db.mjs';
import { protectDefinition, viewDefinition, redact } from './secrets.mjs';
import { runFlow, validateFlow } from './engine.mjs';

const scrypt = promisify(scryptCallback);
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
export const db = createDatabase();
const isProd = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3001);
const sessionsMaxAge = 30 * 24 * 60 * 60 * 1000;
const rates = new Map();
const planLimits = { free: { automations: 3, executions: 500 }, starter: { automations: 20, executions: 2500 }, pro: { automations: 100, executions: 10000 }, business: { automations: 500, executions: 50000 } };
const maxTotalAutomations = 1000;

function json(res, status, value, headers = {}) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'same-origin', ...headers });
  res.end(body);
}

function cookie(req, name) {
  return (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}

function setSessionCookie(res, token, clear = false) {
  const secure = isProd ? '; Secure' : '';
  res.setHeader('set-cookie', `autoflow_session=${clear ? '' : token}; Path=/; HttpOnly; SameSite=Strict${secure}; Max-Age=${clear ? 0 : Math.floor(sessionsMaxAge / 1000)}`);
}

function hashToken(token) { return createHash('sha256').update(token).digest('hex'); }

function rateLimit(req, key, max, windowMs) {
  const forwarded = process.env.TRUST_PROXY === 'true' ? req.headers['x-forwarded-for'] : '';
  const remote = String(forwarded || req.socket.remoteAddress || 'local').split(',')[0].trim();
  const id = `${key}:${remote}`;
  const now = Date.now();
  const entry = rates.get(id);
  if (!entry || entry.reset < now) { rates.set(id, { count: 1, reset: now + windowMs }); return true; }
  entry.count += 1;
  return entry.count <= max;
}

async function bodyJson(req, max = 1024 * 1024) {
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (!contentType.startsWith('application/json')) throw Object.assign(new Error('Envie o conteúdo como application/json.'), { statusCode: 415 });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > max) throw Object.assign(new Error('O corpo da requisição excede o limite permitido.'), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('Envie um documento JSON válido.'), { statusCode: 400 }); }
}

function safeText(value, max, label) {
  if (typeof value !== 'string' || !value.trim()) throw Object.assign(new Error(`${label} é obrigatório.`), { statusCode: 400 });
  if (value.length > max) throw Object.assign(new Error(`${label} excede o limite de ${max} caracteres.`), { statusCode: 400 });
  return value.trim();
}

function parseJson(text, fallback) { try { return JSON.parse(text); } catch { return fallback; } }

async function currentUser(req) {
  const token = cookie(req, 'autoflow_session');
  if (!token) return null;
  return db.get('SELECT u.id, u.email, u.name, wm.workspace_id, wm.role, w.name AS workspace_name, w.plan FROM sessions s JOIN users u ON u.id = s.user_id JOIN workspace_members wm ON wm.user_id = u.id JOIN workspaces w ON w.id = wm.workspace_id WHERE s.token_hash = ? AND s.expires_at > ? ORDER BY w.created_at LIMIT 1', hashToken(decodeURIComponent(token)), new Date().toISOString());
}

function userView(user) {
  return user ? { id: user.id, email: user.email, name: user.name, workspace: { id: user.workspace_id, name: user.workspace_name, role: user.role, plan: user.plan } } : null;
}

function assertOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  const allowed = process.env.PUBLIC_ORIGIN;
  if (allowed && origin === allowed) return;
  if (!isProd && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return;
  const host = req.headers.host;
  if (host && new URL(origin).host === host) return;
  throw Object.assign(new Error('Origem não permitida.'), { statusCode: 403 });
}

function defaultDefinition() {
  return {
    nodes: [
      { id: 'trigger', type: 'manualTrigger', position: { x: 80, y: 180 }, data: { label: 'Início manual', config: {} } },
      { id: 'log', type: 'internalLog', position: { x: 360, y: 180 }, data: { label: 'Registrar atividade', config: { message: 'Fluxo executado com sucesso.' } } },
    ],
    edges: [{ id: 'trigger-log', source: 'trigger', target: 'log', type: 'smoothstep' }],
  };
}

function automationView(row) {
  return { id: row.id, name: row.name, description: row.description, active: Boolean(row.active), version: row.version, definition: viewDefinition(parseJson(row.definition, defaultDefinition())), createdAt: row.created_at, updatedAt: row.updated_at, runCount: Number(row.run_count || 0), lastRunAt: row.last_run_at || null, lastRunStatus: row.last_run_status || null };
}

async function getAutomation(workspaceId, id) {
  return db.get('SELECT a.*, (SELECT COUNT(*) FROM executions e WHERE e.automation_id = a.id) AS run_count, (SELECT e.started_at FROM executions e WHERE e.automation_id = a.id ORDER BY e.started_at DESC LIMIT 1) AS last_run_at, (SELECT e.status FROM executions e WHERE e.automation_id = a.id ORDER BY e.started_at DESC LIMIT 1) AS last_run_status FROM automations a WHERE a.id = ? AND a.workspace_id = ?', id, workspaceId);
}

async function activeExecutionCount(workspaceId) {
  const month = new Date();
  month.setUTCDate(1); month.setUTCHours(0, 0, 0, 0);
  const row = await db.get('SELECT COUNT(*) AS count FROM executions WHERE workspace_id = ? AND started_at >= ?', workspaceId, month.toISOString());
  return Number(row?.count || 0);
}

async function getPlan(user) {
  const plan = user.plan || 'free';
  return { name: plan, ...(planLimits[plan] || planLimits.free) };
}

export async function route(req, res) {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;
  if (path.startsWith('/api/')) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) assertOrigin(req);
    if (req.method === 'OPTIONS') { res.writeHead(204, { allow: 'GET, POST, PUT, PATCH, DELETE, OPTIONS' }); return res.end(); }
  }

  if (req.method === 'GET' && path === '/api/health') return json(res, 200, { status: 'ok', database: db.kind });
  if (req.method === 'GET' && path === '/api/auth/session') {
    const user = await currentUser(req);
    return json(res, 200, { user: userView(user) });
  }
  if (req.method === 'POST' && ['/api/auth/register', '/api/auth/login'].includes(path)) {
    if (!rateLimit(req, path, 8, 60_000)) return json(res, 429, { error: 'Muitas tentativas. Aguarde um minuto e tente novamente.' });
    const body = await bodyJson(req, 32 * 1024);
    const email = safeText(String(body.email || '').toLowerCase(), 254, 'E-mail');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { error: 'Informe um e-mail válido.' });
    if (path.endsWith('register')) {
      const name = safeText(body.name, 80, 'Nome');
      if (typeof body.password !== 'string' || body.password.length < 10 || body.password.length > 256) return json(res, 400, { error: 'A senha precisa ter entre 10 e 256 caracteres.' });
      const exists = await db.get('SELECT id FROM users WHERE email = ?', email);
      if (exists) return json(res, 409, { error: 'Já existe uma conta com este e-mail.' });
      const userId = randomUUID(); const workspaceId = randomUUID(); const now = new Date().toISOString();
      const salt = randomBytes(16).toString('hex');
      const hash = (await scrypt(body.password, salt, 64)).toString('hex');
      await db.transaction(async (tx) => {
        await tx.run('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)', userId, email, name, `${salt}:${hash}`, now);
        await tx.run('INSERT INTO workspaces (id, name, plan, created_at) VALUES (?, ?, ?, ?)', workspaceId, `${name} workspace`, 'free', now);
        await tx.run('INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)', workspaceId, userId, 'owner');
        await tx.run('INSERT INTO audit_logs (id, workspace_id, user_id, action, target_id, created_at) VALUES (?, ?, ?, ?, ?, ?)', randomUUID(), workspaceId, userId, 'account.created', userId, now);
      });
      const token = randomBytes(32).toString('base64url');
      await db.run('INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)', hashToken(token), userId, new Date(Date.now() + sessionsMaxAge).toISOString(), now);
      const user = await currentUser({ headers: { cookie: `autoflow_session=${token}` } });
      setSessionCookie(res, token);
      return json(res, 201, { user: userView(user) });
    }
    if (typeof body.password !== 'string' || body.password.length > 256) return json(res, 400, { error: 'E-mail ou senha inválidos.' });
    const row = await db.get('SELECT * FROM users WHERE email = ?', email);
    let valid = false;
    if (row) {
      const [salt, expected] = row.password_hash.split(':');
      const candidate = await scrypt(body.password, salt, 64);
      valid = timingSafeEqual(candidate, Buffer.from(expected, 'hex'));
    }
    if (!valid) return json(res, 401, { error: 'E-mail ou senha inválidos.' });
    const token = randomBytes(32).toString('base64url'); const now = new Date().toISOString();
    await db.run('INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)', hashToken(token), row.id, new Date(Date.now() + sessionsMaxAge).toISOString(), now);
    const user = await currentUser({ headers: { cookie: `autoflow_session=${token}` } });
    setSessionCookie(res, token);
    return json(res, 200, { user: userView(user) });
  }
  if (req.method === 'POST' && path === '/api/auth/logout') {
    const token = cookie(req, 'autoflow_session');
    if (token) await db.run('DELETE FROM sessions WHERE token_hash = ?', hashToken(decodeURIComponent(token)));
    setSessionCookie(res, '', true);
    return json(res, 200, { ok: true });
  }

  const user = await currentUser(req);
  if (!user) return json(res, 401, { error: 'Entre na sua conta para continuar.' });
  const workspaceId = user.workspace_id;

  if (req.method === 'GET' && path === '/api/dashboard') {
    const [flows, active, recent, fail, monthCount, plan] = await Promise.all([
      db.get('SELECT COUNT(*) AS count FROM automations WHERE workspace_id = ?', workspaceId),
      db.get('SELECT COUNT(*) AS count FROM automations WHERE workspace_id = ? AND active = 1', workspaceId),
      db.all('SELECT e.id, e.automation_id, a.name AS automation_name, e.status, e.started_at, e.duration_ms FROM executions e JOIN automations a ON a.id = e.automation_id WHERE e.workspace_id = ? ORDER BY e.started_at DESC LIMIT 6', workspaceId),
      db.get("SELECT COUNT(*) AS count FROM executions WHERE workspace_id = ? AND status = 'failed' AND started_at >= ?", workspaceId, new Date(Date.now() - 30 * 86400_000).toISOString()),
      activeExecutionCount(workspaceId), getPlan(user),
    ]);
    const monthStart = new Date(); monthStart.setUTCDate(1); monthStart.setUTCHours(0, 0, 0, 0);
    const total = await db.get('SELECT COUNT(*) AS count FROM executions WHERE workspace_id = ? AND started_at >= ?', workspaceId, monthStart.toISOString());
    const successes = await db.get("SELECT COUNT(*) AS count FROM executions WHERE workspace_id = ? AND started_at >= ? AND status = 'completed'", workspaceId, monthStart.toISOString());
    const totalCount = Number(total.count || 0);
    return json(res, 200, { metrics: { automations: Number(flows.count), active: Number(active.count), executionsThisMonth: monthCount, monthlyLimit: plan.executions, successRate: totalCount ? Math.round(Number(successes.count) / totalCount * 100) : 0, failures30d: Number(fail.count) }, recent: recent.map((r) => ({ id: r.id, automationId: r.automation_id, automationName: r.automation_name, status: r.status, startedAt: r.started_at, durationMs: r.duration_ms })) });
  }
  if (req.method === 'GET' && path === '/api/templates') {
    return json(res, 200, { templates: [
      { id: 'manual-log', name: 'Registrar uma atividade', description: 'Inicie manualmente um fluxo e confira o registro no histórico.', category: 'Operações', definition: defaultDefinition() },
      { id: 'discord-message', name: 'Notificar um canal Discord', description: 'Configure um webhook para enviar uma mensagem após a execução manual.', category: 'Notificações', definition: { nodes: [{ id: 'trigger', type: 'manualTrigger', position: { x: 80, y: 180 }, data: { label: 'Início manual', config: {} } }, { id: 'discord', type: 'discord', position: { x: 400, y: 180 }, data: { label: 'Enviar ao Discord', config: { webhookUrl: '', message: 'Nova atividade: {{ trigger.body.message }}' } } }], edges: [{ id: 'e1', source: 'trigger', target: 'discord' }] } },
      { id: 'http-log', name: 'Conferir uma API', description: 'Faça uma requisição HTTP e registre o resultado.', category: 'Desenvolvimento', definition: { nodes: [{ id: 'trigger', type: 'manualTrigger', position: { x: 80, y: 180 }, data: { label: 'Início manual', config: {} } }, { id: 'request', type: 'httpRequest', position: { x: 360, y: 180 }, data: { label: 'Consultar API', config: { method: 'GET', url: 'https://api.github.com', headers: '{"accept":"application/json"}' } } }, { id: 'log', type: 'internalLog', position: { x: 640, y: 180 }, data: { label: 'Registrar resultado', config: { message: 'Consulta concluída.' } } }], edges: [{ id: 'e1', source: 'trigger', target: 'request' }, { id: 'e2', source: 'request', target: 'log' }] } },
      { id: 'condition-log', name: 'Avaliar uma condição', description: 'Decida entre duas saídas e registre a trilha executada.', category: 'Lógica', definition: { nodes: [{ id: 'trigger', type: 'manualTrigger', position: { x: 80, y: 180 }, data: { label: 'Início manual', config: {} } }, { id: 'condition', type: 'condition', position: { x: 360, y: 180 }, data: { label: 'Verificar condição', config: { field: 'trigger.aprovado', operator: 'equals', value: 'true' } } }, { id: 'yes', type: 'internalLog', position: { x: 680, y: 90 }, data: { label: 'Caminho aprovado', config: { message: 'Condição verdadeira.' } } }, { id: 'no', type: 'internalLog', position: { x: 680, y: 280 }, data: { label: 'Caminho alternativo', config: { message: 'Condição falsa.' } } }], edges: [{ id: 'e1', source: 'trigger', target: 'condition' }, { id: 'e2', source: 'condition', sourceHandle: 'true', target: 'yes', label: 'Verdadeiro' }, { id: 'e3', source: 'condition', sourceHandle: 'false', target: 'no', label: 'Falso' }] } },
    ] });
  }
  if (req.method === 'GET' && path === '/api/automations') {
    const rows = await db.all('SELECT a.*, (SELECT COUNT(*) FROM executions e WHERE e.automation_id = a.id) AS run_count, (SELECT e.started_at FROM executions e WHERE e.automation_id = a.id ORDER BY e.started_at DESC LIMIT 1) AS last_run_at, (SELECT e.status FROM executions e WHERE e.automation_id = a.id ORDER BY e.started_at DESC LIMIT 1) AS last_run_status FROM automations a WHERE a.workspace_id = ? ORDER BY a.updated_at DESC', workspaceId);
    return json(res, 200, { automations: rows.map(automationView) });
  }
  if (req.method === 'POST' && path === '/api/automations') {
    const body = await bodyJson(req);
    const count = await db.get('SELECT COUNT(*) AS count FROM automations WHERE workspace_id = ?', workspaceId);
    if (Number(count.count) >= maxTotalAutomations) return json(res, 403, { error: `Este workspace atingiu o limite operacional de ${maxTotalAutomations} fluxos.` });
    const id = randomUUID(); const now = new Date().toISOString();
    const name = safeText(body.name || 'Nova automação', 120, 'Nome');
    const description = typeof body.description === 'string' ? body.description.slice(0, 500) : '';
    const definition = protectDefinition(body.definition || defaultDefinition());
    await db.run('INSERT INTO automations (id, workspace_id, name, description, active, version, definition, created_at, updated_at) VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?)', id, workspaceId, name, description, JSON.stringify(definition), now, now);
    await db.run('INSERT INTO audit_logs (id, workspace_id, user_id, action, target_id, created_at) VALUES (?, ?, ?, ?, ?, ?)', randomUUID(), workspaceId, user.id, 'automation.created', id, now);
    return json(res, 201, { automation: automationView(await getAutomation(workspaceId, id)) });
  }

  const automationRoute = path.match(/^\/api\/automations\/([\w-]+)(?:\/(run|toggle|duplicate|validate))?$/);
  if (automationRoute) {
    const [, id, action] = automationRoute;
    const row = await getAutomation(workspaceId, id);
    if (!row) return json(res, 404, { error: 'Automação não encontrada.' });
    if (req.method === 'GET' && !action) return json(res, 200, { automation: automationView(row) });
    if (req.method === 'POST' && action === 'validate') {
      const errors = validateFlow(parseJson(row.definition, defaultDefinition()));
      return json(res, errors.length ? 422 : 200, { valid: errors.length === 0, errors });
    }
    if (req.method === 'PUT' && !action) {
      const body = await bodyJson(req);
      const name = safeText(body.name, 120, 'Nome');
      const description = typeof body.description === 'string' ? body.description.slice(0, 500) : '';
      const previous = parseJson(row.definition, defaultDefinition());
      const definition = protectDefinition(body.definition, previous);
      const now = new Date().toISOString();
      await db.run('UPDATE automations SET name = ?, description = ?, definition = ?, version = version + 1, updated_at = ? WHERE id = ? AND workspace_id = ?', name, description, JSON.stringify(definition), now, id, workspaceId);
      await db.run('INSERT INTO audit_logs (id, workspace_id, user_id, action, target_id, created_at) VALUES (?, ?, ?, ?, ?, ?)', randomUUID(), workspaceId, user.id, 'automation.updated', id, now);
      return json(res, 200, { automation: automationView(await getAutomation(workspaceId, id)) });
    }
    if (req.method === 'POST' && action === 'toggle') {
      const body = await bodyJson(req, 32 * 1024);
      const next = body.active === undefined ? !Boolean(row.active) : Boolean(body.active);
      if (next) {
        const errors = validateFlow(parseJson(row.definition, defaultDefinition()));
        if (errors.length) return json(res, 400, { error: errors[0], validation: errors });
        const plan = await getPlan(user);
        const active = await db.get('SELECT COUNT(*) AS count FROM automations WHERE workspace_id = ? AND active = 1', workspaceId);
        if (!row.active && Number(active.count) >= plan.automations) return json(res, 403, { error: `O plano ${plan.name} permite até ${plan.automations} automações ativas.` });
      }
      const now = new Date().toISOString();
      await db.run('UPDATE automations SET active = ?, updated_at = ? WHERE id = ? AND workspace_id = ?', next ? 1 : 0, now, id, workspaceId);
      await db.run('INSERT INTO audit_logs (id, workspace_id, user_id, action, target_id, created_at) VALUES (?, ?, ?, ?, ?, ?)', randomUUID(), workspaceId, user.id, next ? 'automation.activated' : 'automation.deactivated', id, now);
      return json(res, 200, { automation: automationView(await getAutomation(workspaceId, id)) });
    }
    if (req.method === 'POST' && action === 'duplicate') {
      const count = await db.get('SELECT COUNT(*) AS count FROM automations WHERE workspace_id = ?', workspaceId);
      if (Number(count.count) >= maxTotalAutomations) return json(res, 403, { error: `Este workspace atingiu o limite operacional de ${maxTotalAutomations} fluxos.` });
      const newId = randomUUID(); const now = new Date().toISOString();
      await db.run('INSERT INTO automations (id, workspace_id, name, description, active, version, definition, created_at, updated_at) VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?)', newId, workspaceId, `${row.name} (cópia)`.slice(0, 120), row.description, row.definition, now, now);
      return json(res, 201, { automation: automationView(await getAutomation(workspaceId, newId)) });
    }
    if (req.method === 'POST' && action === 'run') {
      if (!rateLimit(req, 'run', 30, 60_000)) return json(res, 429, { error: 'Muitas execuções. Aguarde um minuto e tente novamente.' });
      const key = req.headers['idempotency-key'] ? String(req.headers['idempotency-key']).slice(0, 100) : null;
      if (key) {
        const prior = await db.get('SELECT * FROM executions WHERE workspace_id = ? AND idempotency_key = ?', workspaceId, key);
        if (prior) return json(res, prior.status === 'running' || prior.status === 'pending' ? 202 : 200, { execution: { id: prior.id, status: prior.status, steps: parseJson(prior.steps_json, []), error: redact(prior.error_message) } });
      }
      const used = await activeExecutionCount(workspaceId);
      const plan = await getPlan(user);
      if (used >= plan.executions) return json(res, 403, { error: `O limite mensal de ${plan.executions} execuções do plano ${plan.name} foi atingido.` });
      const body = await bodyJson(req, 128 * 1024);
      const payload = body.input === undefined ? {} : body.input;
      if (payload === null || typeof payload !== 'object') return json(res, 400, { error: 'Os dados de entrada precisam ser um objeto JSON ou uma lista.' });
      try {
        const execution = await runFlow(db, workspaceId, row, payload, { idempotencyKey: key });
        return json(res, 200, { execution });
      } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE' || error.code === '23505') {
          const prior = key && await db.get('SELECT * FROM executions WHERE workspace_id = ? AND idempotency_key = ?', workspaceId, key);
          if (prior) return json(res, 200, { execution: { id: prior.id, status: prior.status, steps: parseJson(prior.steps_json, []) } });
        }
        if (error.executionId) return json(res, 422, { error: redact(error.message), executionId: error.executionId, validation: error.validation || undefined });
        throw error;
      }
    }
    if (req.method === 'DELETE' && !action) {
      const now = new Date().toISOString();
      await db.run('INSERT INTO audit_logs (id, workspace_id, user_id, action, target_id, created_at) VALUES (?, ?, ?, ?, ?, ?)', randomUUID(), workspaceId, user.id, 'automation.deleted', id, now);
      await db.run('DELETE FROM automations WHERE id = ? AND workspace_id = ?', id, workspaceId);
      return json(res, 200, { ok: true });
    }
  }

  if (req.method === 'GET' && path === '/api/executions') {
    const status = url.searchParams.get('status');
    const search = url.searchParams.get('search');
    const automationId = url.searchParams.get('automationId');
    const conditions = ['e.workspace_id = ?']; const args = [workspaceId];
    if (status && ['pending', 'running', 'completed', 'failed', 'cancelled'].includes(status)) { conditions.push('e.status = ?'); args.push(status); }
    if (search) { conditions.push('LOWER(a.name) LIKE LOWER(?)'); args.push(`%${search.slice(0, 100)}%`); }
    if (automationId) { conditions.push('e.automation_id = ?'); args.push(automationId); }
    const rows = await db.all(`SELECT e.id, e.automation_id, a.name AS automation_name, e.status, e.started_at, e.finished_at, e.duration_ms, e.error_message, e.steps_json FROM executions e JOIN automations a ON a.id = e.automation_id WHERE ${conditions.join(' AND ')} ORDER BY e.started_at DESC LIMIT 100`, ...args);
    return json(res, 200, { executions: rows.map((r) => ({ id: r.id, automationId: r.automation_id, automationName: r.automation_name, status: r.status, startedAt: r.started_at, finishedAt: r.finished_at, durationMs: r.duration_ms, error: redact(r.error_message), steps: parseJson(r.steps_json, []) })) });
  }
  const executionMatch = path.match(/^\/api\/executions\/([\w-]+)$/);
  if (req.method === 'GET' && executionMatch) {
    const row = await db.get('SELECT e.*, a.name AS automation_name FROM executions e JOIN automations a ON a.id = e.automation_id WHERE e.id = ? AND e.workspace_id = ?', executionMatch[1], workspaceId);
    if (!row) return json(res, 404, { error: 'Execução não encontrada.' });
    return json(res, 200, { execution: { id: row.id, automationId: row.automation_id, automationName: row.automation_name, status: row.status, input: parseJson(row.input_json, {}), steps: parseJson(row.steps_json, []), error: redact(row.error_message), startedAt: row.started_at, finishedAt: row.finished_at, durationMs: row.duration_ms, attempt: row.attempt } });
  }

  if (path.startsWith('/api/')) return json(res, 404, { error: 'Rota não encontrada.' });
  return serveStatic(path, res);
}

const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };
function serveStatic(path, res) {
  const dist = resolve(root, 'dist');
  if (!existsSync(dist)) return json(res, 404, { error: 'Frontend ainda não foi compilado. Execute npm run build.' });
  const candidate = resolve(dist, `.${decodeURIComponent(path)}`);
  const file = candidate.startsWith(dist + sep) && existsSync(candidate) ? candidate : resolve(dist, 'index.html');
  res.writeHead(200, { 'content-type': mime[extname(file)] || 'application/octet-stream', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'" });
  createReadStream(file).pipe(res);
}

await db.migrate();
if (process.env.AUTOFLOW_NO_LISTEN !== 'true') {
  const server = createServer((req, res) => {
    route(req, res).catch((error) => {
      if (res.headersSent) { res.destroy(); return; }
      const status = Number(error.statusCode) || 500;
      const message = status < 500 ? error.message : 'Ocorreu um erro ao processar a solicitação.';
      if (status >= 500) console.error(`[autoflow] request failed: ${req.method} ${req.url}`);
      json(res, status, { error: redact(message), ...(error.validation ? { validation: error.validation } : {}) });
    });
  });
  const host = process.env.HOST || (isProd ? '0.0.0.0' : '127.0.0.1');
  server.listen(port, host, () => console.log(`AutoFlow API: http://${host}:${port} (${db.kind})`));
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { server.close(); await db.close(); process.exit(0); });
}
