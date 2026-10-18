import { json } from '../../_lib.js';
async function listAll(kv, prefix) {
  const out = []; let cursor;
  do {
    const r = await kv.list({ prefix, cursor });
    for (const k of r.keys) out.push(k.name.slice(prefix.length));
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor);
  return out;
}
export async function onRequestGet({ env }) {
  const kv = env.AUTH_KV;
  const pendingEmails = await listAll(kv, 'pending:');
  const pending = [];
  for (const e of pendingEmails) { let v = {}; try { v = JSON.parse(await kv.get('pending:' + e)) || {}; } catch {} pending.push({ email: e, ...v }); }
  pending.sort((a, b) => String(a.at).localeCompare(String(b.at)));
  const users = (await listAll(kv, 'user:')).sort();
  const denied = (await listAll(kv, 'denied:')).sort();
  return json({ pending, users, denied });
}
