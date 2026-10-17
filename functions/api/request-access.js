import { verifyGoogleToken, readSession, json, rateLimit, notifyTelegram } from '../_lib.js';

export async function onRequestPost({ request, env }) {
  const ip = request.headers.get('CF-Connecting-IP') || 'x';
  if (!(await rateLimit(env, 'req:' + ip, 10, 86400))) return json({ error: 'trop_de_demandes' }, 429);
  let body; try { body = await request.json(); } catch { return json({ error: 'requete_invalide' }, 400); }
  // Identité prouvée par Google (jeton frais) ou par la session "en attente" déjà établie.
  let email = null, name = '';
  const g = body.credential ? await verifyGoogleToken(env, body.credential) : null;
  if (g) { email = g.email; name = g.name; } else { email = await readSession(env, request); }
  if (!email) return json({ error: 'non_identifie' }, 401);

  if ((await env.AUTH_KV.get('user:' + email)) !== null) return json({ status: 'deja_approuve' });
  if ((await env.AUTH_KV.get('denied:' + email)) !== null) return json({ status: 'denied' });
  if ((await env.AUTH_KV.get('pending:' + email)) !== null) return json({ status: 'pending' });

  const message = String(body.message || '').slice(0, 300);
  await env.AUTH_KV.put('pending:' + email, JSON.stringify({ name: name || String(body.name || '').slice(0, 80), message, at: new Date().toISOString() }));
  await notifyTelegram(env, `🛒 Nouvelle demande d'accès au calculateur : ${email}${message ? '\n« ' + message + ' »' : ''}`);
  return json({ status: 'pending' });
}
