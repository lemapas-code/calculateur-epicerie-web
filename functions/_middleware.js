// Garde d'accès : tout est protégé sauf les pages de connexion et leurs API.
import { readSession, isApproved, isAdmin, json } from './_lib.js';

const PUBLIC = new Set(['/login', '/login.html', '/api/google-login', '/api/request-access', '/api/logout', '/api/config', '/favicon.ico']);

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  // La liste d'accès ne doit jamais être téléchargeable.
  if (path === '/acces.txt' || path === '/acces.csv') return new Response('Not found', { status: 404 });

  if (PUBLIC.has(path)) return next();

  if (!env.AUTH_KV || !env.SESSION_SECRET || !env.GOOGLE_CLIENT_ID || !env.ADMIN_EMAIL) {
    return new Response('Configuration incomplète (variables manquantes). Voir le guide de déploiement.', { status: 500 });
  }

  const email = await readSession(env, request);
  const ok = await isApproved(env, email, url.origin); // vérifié à chaque requête : retirer quelqu'un coupe l'accès tout de suite

  if (!ok) {
    if (path.startsWith('/api/')) return json({ error: 'non_autorise' }, 401);
    return Response.redirect(url.origin + '/login', 302);
  }

  // La page d'administration n'est réservée qu'à l'admin.
  if ((path === '/admin' || path === '/admin.html') && !isAdmin(env, email)) return Response.redirect(url.origin + '/', 302);

  // La page d'accueil sert le calculateur (le fichier garde son nom d'origine).
  if (path === '/') {
    const asset = new URL(request.url);
    asset.pathname = '/calculateur-prix-epicerie';   // Pages retire ".html" des URL
    let res = await env.ASSETS.fetch(new Request(asset, request));
    if (res.status >= 300 && res.status < 400 && res.headers.get('Location')) {
      res = await env.ASSETS.fetch(new Request(new URL(res.headers.get('Location'), asset), request));
    }
    const out = new Response(res.body, res);
    out.headers.set('Cache-Control', 'private, no-store');
    return out;
  }
  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'private, no-store');
  return out;
}
