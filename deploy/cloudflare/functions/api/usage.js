// Cloudflare Pages Function: POST /api/usage

export async function onRequestPost(context) {
  const { request, env } = context;

  const { apiKey, action } = await request.json();

  // TODO: Increment in KV or D1
  // const month = new Date().toISOString().slice(0, 7);
  // const key = `usage:${apiKey}:${month}`;
  // const current = parseInt(await env.USERS_KV.get(key) || '0');
  // await env.USERS_KV.put(key, String(current + 1));

  console.log(`[Usage] Key: ${apiKey?.slice(0, 12)}..., Action: ${action}`);

  return Response.json({ recorded: true });
}
