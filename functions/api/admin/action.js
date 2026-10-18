import { json, normEmail, validEmail } from '../../_lib.js';

// POST { action: approve|deny|remove|undeny|add, email } ou { action: 'import', emails: [...] }
export async function onRequestPost({ request, env }) {
  let b; try { b = await request.json(); } catch { return json({ error: 'requete_invalide' }, 400); }
  const kv = env.AUTH_KV;
  const stamp = JSON.stringify({ at: new Date().toISOString() });
  const setUser = async e => { await kv.put('user:' + e, stamp); await kv.delete('pending:' + e); await kv.delete('denied:' + e); };

  if (b.action === 'import') {
    const list = [...new Set((b.emails || []).map(normEmail).filter(validEmail))].slice(0, 5000);
    for (const e of list) await setUser(e);
    return json({ status: 'ok', importes: list.length });
  }
  const email = normEmail(b.email);
  if (!validEmail(email)) return json({ error: 'courriel_invalide' }, 400);
  switch (b.action) {
    case 'approve': case 'add': await setUser(email); break;
    case 'deny': await kv.put('denied:' + email, stamp); await kv.delete('pending:' + email); break;
    case 'undeny': await kv.delete('denied:' + email); break;
    case 'remove': await kv.delete('user:' + email); break;
    default: return json({ error: 'action_inconnue' }, 400);
  }
  return json({ status: 'ok' });
}
