export async function onRequestPost(context) {
  const { request, env } = context;
  const db = env.DB;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ valid: false, error: 'Invalid request' }, { status: 400 });
  }

  const { apiKey } = body;
  if (!apiKey) {
    return Response.json({ valid: false, error: 'API key required' }, { status: 400 });
  }

  const sub = await db
    .prepare('SELECT plan, status FROM subscriptions WHERE api_key = ?')
    .bind(apiKey)
    .first();

  if (!sub || sub.status !== 'active') {
    return Response.json({ valid: false }, { status: 401 });
  }

  // Get current month usage
  const month = new Date().toISOString().slice(0, 7); // YYYY-MM
  const usage = await db
    .prepare('SELECT count FROM usage WHERE api_key = ? AND month = ?')
    .bind(apiKey, month)
    .first();

  const used = usage?.count || 0;
  const limit = sub.plan === 'team' ? 2000 : 200;

  return Response.json({
    valid: true,
    plan: sub.plan,
    remaining: Math.max(0, limit - used),
    limit,
  });
}
