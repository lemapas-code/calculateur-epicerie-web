import { clearCookie } from '../_lib.js';
export async function onRequest() {
  return new Response(null, { status: 302, headers: { Location: '/login', 'Set-Cookie': clearCookie, 'Cache-Control': 'no-store' } });
}
