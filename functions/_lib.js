// Utilitaires partagés (cookie de session signé, KV, réponses JSON).
const enc = new TextEncoder();

export const COOKIE = 'cpe_session';
export const SESSION_DAYS = 30;

export function normEmail(e) { return String(e || '').trim().toLowerCase(); }
export function validEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254; }

function b64url(buf) {
  let s = '';
  new Uint8Array(buf).forEach(b => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function makeSession(env, email) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  const payload = b64url(enc.encode(JSON.stringify({ e: email, x: exp })));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env.SESSION_SECRET), enc.encode(payload));
  return `${payload}.${b64url(sig)}`;
}

export async function readSession(env, request) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|; )' + COOKIE + '=([^;]+)'));
  if (!m || !env.SESSION_SECRET) return null;
  const [payload, sig] = m[1].split('.');
  if (!payload || !sig) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env.SESSION_SECRET), fromB64url(sig), enc.encode(payload));
    if (!ok) return null;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    if (!data.e || data.x < Math.floor(Date.now() / 1000)) return null;
    return normEmail(data.e);
  } catch { return null; }
}

export function sessionCookie(value, maxAgeDays = SESSION_DAYS) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeDays * 86400}`;
}
export const clearCookie = `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

export function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers } });
}

export function isAdmin(env, email) {
  return !!email && normEmail(env.ADMIN_EMAIL) === email;
}

// Un utilisateur a accès s'il est l'admin ou approuvé dans la liste.
export async function isApproved(env, email) {
  if (!email) return false;
  if (isAdmin(env, email)) return true;
  return (await env.AUTH_KV.get('user:' + email)) !== null;
}

// Limiteur simple : max `limit` actions par fenêtre, par clé.
export async function rateLimit(env, key, limit, windowSec) {
  const k = 'rl:' + key;
  const n = parseInt((await env.AUTH_KV.get(k)) || '0', 10);
  if (n >= limit) return false;
  await env.AUTH_KV.put(k, String(n + 1), { expirationTtl: Math.max(60, windowSec) });
  return true;
}

// Vérifie un jeton d'identité Google (via l'endpoint officiel tokeninfo).
export async function verifyGoogleToken(env, credential) {
  if (!credential || typeof credential !== 'string' || credential.length > 4096) return null;
  const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential));
  if (!r.ok) return null;
  const t = await r.json();
  if (t.aud !== env.GOOGLE_CLIENT_ID) return null;
  if (!(t.iss === 'accounts.google.com' || t.iss === 'https://accounts.google.com')) return null;
  if (String(t.email_verified) !== 'true') return null;
  if (parseInt(t.exp, 10) < Math.floor(Date.now() / 1000)) return null;
  return { email: normEmail(t.email), name: t.name || '' };
}

// Notification Telegram facultative (aucun frais) quand quelqu'un demande l'accès.
export async function notifyTelegram(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text })
    });
  } catch {}
}
