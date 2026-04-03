export async function onRequestPost(context) {
  const { request, env } = context;
  const db = env.DB;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid request' }, { status: 400 });
  }

  const { customer_id } = body;
  if (!customer_id) {
    return Response.json({ error: 'customer_id required' }, { status: 400 });
  }

  const sub = await db
    .prepare('SELECT api_key, plan FROM subscriptions WHERE customer_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1')
    .bind(customer_id, 'active')
    .first();

  if (!sub) {
    return Response.json({ found: false }, { status: 404 });
  }

  return Response.json({
    found: true,
    api_key: sub.api_key,
    plan: sub.plan,
  });
}
