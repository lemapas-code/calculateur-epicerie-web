import { verifyGoogleToken, isApproved, makeSession, sessionCookie, json, rateLimit } from '../_lib.js';

export async function onRequestPost({ request, env }) {
  const ip = request.headers.get('CF-Connecting-IP') || 'x';
  if (!(await rateLimit(env, 'login:' + ip, 30, 600))) return json({ error: 'trop_de_tentatives' }, 429);
  let body; try { body = await request.json(); } catch { return json({ error: 'requete_invalide' }, 400); }
  const user = await verifyGoogleToken(env, body.credential);
  if (!user) return json({ error: 'jeton_invalide' }, 401);

  if (await isApproved(env, user.email, new URL(request.url).origin)) {
    const token = await makeSession(env, user.email);
    return json({ status: 'ok', email: user.email }, 200, { 'Set-Cookie': sessionCookie(token) });
  }
  // Connecté chez Google mais pas encore approuvé : on mémorise une session "en attente"
  // (cookie signé, sans accès) pour permettre de demander l'accès en un clic.
  const pending = (await env.AUTH_KV.get('pending:' + user.email)) !== null;
  const denied = (await env.AUTH_KV.get('denied:' + user.email)) !== null;
  const token = await makeSession(env, user.email);
  return json({ status: denied ? 'denied' : pending ? 'pending' : 'not_approved', email: user.email }, 200, { 'Set-Cookie': sessionCookie(token, 1) });
}
