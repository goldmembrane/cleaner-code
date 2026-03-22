// Cloudflare Pages Function: POST /api/validate-key

export async function onRequestPost(context) {
  const { request, env } = context;

  const { apiKey } = await request.json();

  if (!apiKey) {
    return Response.json({ valid: false, error: 'API key required' }, { status: 400 });
  }

  // TODO: Lookup in KV or D1
  // const userData = await env.USERS_KV.get(`key:${apiKey}`, 'json');
  // if (!userData || userData.status !== 'active') {
  //   return Response.json({ valid: false }, { status: 401 });
  // }

  // Placeholder
  return Response.json({
    valid: true,
    plan: 'dev',
    remaining: 185,
    limit: 200,
  });
}
