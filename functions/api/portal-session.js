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

  if (!env.PADDLE_API_KEY) {
    return Response.json(
      { error: 'Paddle API not configured' },
      { status: 500 }
    );
  }

  const sub = await db
    .prepare(
      'SELECT customer_id FROM subscriptions WHERE email = ? AND status = ? ORDER BY created_at DESC LIMIT 1'
    )
    .bind(email, 'active')
    .first();

  if (!sub) {
    return Response.json(
      { error: 'No active subscription found' },
      { status: 404 }
    );
  }

  try {
    const resp = await fetch(
      `https://api.paddle.com/customers/${sub.customer_id}/portal-sessions`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.PADDLE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      }
    );

    const data = await resp.json();

    if (!resp.ok) {
      console.error('Paddle API error:', JSON.stringify(data));
      return Response.json(
        { error: 'Failed to create portal session' },
        { status: 502 }
      );
    }

    const urls = data.data?.urls;
    const portalUrl =
      urls?.general?.overview ||
      urls?.subscriptions?.[0]?.update_subscription_payment_method ||
      null;

    if (!portalUrl) {
      return Response.json(
        { error: 'No portal URL returned from Paddle' },
        { status: 502 }
      );
    }

    return Response.json({ url: portalUrl });
  } catch (err) {
    console.error('Portal session error:', err.message);
    return Response.json(
      { error: 'Failed to connect to Paddle' },
      { status: 502 }
    );
  }
}
