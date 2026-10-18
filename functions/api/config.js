// Donne à la page de connexion l'identifiant client Google (public par nature).
export async function onRequestGet({ env }) {
  return new Response(JSON.stringify({ clientId: env.GOOGLE_CLIENT_ID || '' }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
