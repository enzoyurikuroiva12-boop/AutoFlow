import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const keyPath = resolve(process.env.DATA_DIR || resolve(root, '.data'), 'credentials.key');
let key;

function loadKey() {
  if (key) return key;
  if (process.env.AUTOFLOW_CREDENTIALS_KEY) {
    key = createHash('sha256').update(process.env.AUTOFLOW_CREDENTIALS_KEY).digest();
    return key;
  }
  mkdirSync(dirname(keyPath), { recursive: true });
  if (!existsSync(keyPath)) {
    writeFileSync(keyPath, randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
    try { chmodSync(keyPath, 0o600); } catch {}
  }
  key = Buffer.from(readFileSync(keyPath, 'utf8').trim(), 'hex');
  if (key.length !== 32) throw new Error('A chave local de criptografia está inválida.');
  return key;
}

function encrypt(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', loadKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return `enc:v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${ciphertext.toString('base64')}`;
}

function decrypt(value) {
  if (!value?.startsWith('enc:v1:')) return value;
  const [, , ivText, tagText, bodyText] = value.split(':');
  const decipher = createDecipheriv('aes-256-gcm', loadKey(), Buffer.from(ivText, 'base64'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(bodyText, 'base64')), decipher.final()]).toString('utf8');
}

const secretKey = /(?:secret|password|token|authorization|webhookurl|apikey|api_key)/i;
const MASK = '••••••••';
function sensitive(name, value) {
  if (secretKey.test(name)) return true;
  if (name.toLowerCase() === 'url' && typeof value === 'string' && /[?&](?:token|key|secret|api[_-]?key)=/i.test(value)) return true;
  if (name.toLowerCase() !== 'headers' || typeof value !== 'string') return false;
  if (value === MASK || value.startsWith('enc:v1:')) return true;
  return /"(?:authorization|proxy-authorization|x-api-key|api-key|token|secret)"\s*:/i.test(value);
}

export function protectDefinition(definition, existing = null) {
  const oldNodes = new Map((existing?.nodes || []).map((node) => [node.id, node]));
  const copy = structuredClone(definition);
  for (const node of copy.nodes || []) {
    const old = oldNodes.get(node.id);
    const oldConfig = old?.data?.config || {};
    const config = node.data?.config || {};
    for (const [name, value] of Object.entries(config)) {
      if (!sensitive(name, value) || typeof value !== 'string') continue;
      if (value === MASK && oldConfig[name]) config[name] = oldConfig[name];
      else if (value && !value.startsWith('enc:v1:')) config[name] = encrypt(value);
      else if (!value && oldConfig[name]) config[name] = oldConfig[name];
    }
  }
  return copy;
}

export function viewDefinition(definition) {
  const copy = structuredClone(definition);
  for (const node of copy.nodes || []) {
    for (const [name, value] of Object.entries(node.data?.config || {})) {
      if (sensitive(name, value) && typeof value === 'string' && value) node.data.config[name] = MASK;
    }
  }
  return copy;
}

export function runtimeDefinition(definition) {
  const copy = structuredClone(definition);
  for (const node of copy.nodes || []) {
    for (const [name, value] of Object.entries(node.data?.config || {})) {
      if (sensitive(name, value) && typeof value === 'string') node.data.config[name] = decrypt(value);
    }
  }
  return copy;
}

export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, secretKey.test(key) ? (item ? MASK : item) : redact(item)]));
  }
  if (typeof value === 'string') {
    return value
      .replace(/(\/api\/webhooks\/\d+\/)[^/?\s]+/gi, '$1[redacted]')
      .replace(/([?&](?:token|key|secret)=)[^&\s]+/gi, '$1[redacted]');
  }
  return value;
}

