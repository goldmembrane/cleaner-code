export async function onRequestPost(context) {
  const { request, env } = context;
  const db = env.DB;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid request' }, { status: 400 });
  }

  const { email } = body;
  if (!email) {
    return Response.json({ error: 'Email required' }, { status: 400 });
  }

  const sub = await db
    .prepare(
      'SELECT customer_id, email, plan, period, api_key, status, created_at FROM subscriptions WHERE email = ? ORDER BY created_at DESC LIMIT 1'
    )
    .bind(email)
    .first();

  if (!sub) {
    return Response.json({ found: false }, { status: 404 });
  }

  const key = sub.api_key;
  const masked =
    key.length > 16
      ? key.slice(0, 12) + '...' + key.slice(-4)
      : key.slice(0, 4) + '...';

  const month = new Date().toISOString().slice(0, 7);
  const usage = await db
    .prepare('SELECT count FROM usage WHERE api_key = ? AND month = ?')
    .bind(sub.api_key, month)
    .first();

  const used = usage?.count || 0;
  const limit = sub.plan === 'team' ? 2000 : 200;

  return Response.json({
    found: true,
    email: sub.email,
    plan: sub.plan,
    period: sub.period,
    status: sub.status,
    masked_api_key: masked,
    created_at: sub.created_at,
    usage_used: used,
    usage_limit: limit,
  });
}
