import { readSession, isAdmin, json } from '../../_lib.js';
export async function onRequest({ request, env, next }) {
  const email = await readSession(env, request);
  if (!isAdmin(env, email)) return json({ error: 'admin_seulement' }, 403);
  return next();
}
