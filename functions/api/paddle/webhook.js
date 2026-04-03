export async function onRequestPost(context) {
  const { request, env } = context;

  // Verify webhook signature
  const signature = request.headers.get('paddle-signature');
  const rawBody = await request.text();

  if (env.PADDLE_WEBHOOK_SECRET) {
    if (!signature) {
      return Response.json({ error: 'Missing signature' }, { status: 401 });
    }

    const parts = {};
    signature.split(';').forEach((part) => {
      const [key, value] = part.split('=');
      parts[key] = value;
    });

    const ts = parts['ts'];
    const h1 = parts['h1'];
    if (!ts || !h1) {
      return Response.json({ error: 'Invalid signature format' }, { status: 401 });
    }

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.PADDLE_WEBHOOK_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signed = await crypto.subtle.sign('HMAC', key, encoder.encode(`${ts}:${rawBody}`));
    const expected = [...new Uint8Array(signed)].map((b) => b.toString(16).padStart(2, '0')).join('');

    if (h1 !== expected) {
      return Response.json({ error: 'Invalid signature' }, { status: 401 });
    }
  }

  const event = JSON.parse(rawBody);
  const db = env.DB;

  try {
    switch (event.event_type) {
      case 'subscription.created':
        await handleSubscriptionCreated(db, event.data);
        break;
      case 'subscription.updated':
        await handleSubscriptionUpdated(db, event.data);
        break;
      case 'subscription.canceled':
        await handleSubscriptionCanceled(db, event.data);
        break;
      case 'transaction.completed':
        break;
    }
  } catch (err) {
    console.error(`Webhook error: ${err.message}`);
    return Response.json({ error: 'Internal error' }, { status: 500 });
  }

  return Response.json({ received: true });
}

function generateApiKey() {
  const prefix = 'cc_live_';
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const key = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  return prefix + key;
}

async function handleSubscriptionCreated(db, data) {
  const customerId = data.customer_id;
  const subscriptionId = data.id;
  const email = data.customer?.email || '';
  const plan = data.custom_data?.plan || 'dev';
  const period = data.custom_data?.period || 'monthly';
  const apiKey = generateApiKey();

  await db
    .prepare(
      `INSERT INTO subscriptions (customer_id, subscription_id, email, plan, period, api_key, status)
       VALUES (?, ?, ?, ?, ?, ?, 'active')`
    )
    .bind(customerId, subscriptionId, email, plan, period, apiKey)
    .run();
}

async function handleSubscriptionUpdated(db, data) {
  const subscriptionId = data.id;
  const status = data.status;
  const plan = data.custom_data?.plan;

  if (plan) {
    await db
      .prepare(`UPDATE subscriptions SET status = ?, plan = ?, updated_at = datetime('now') WHERE subscription_id = ?`)
      .bind(status, plan, subscriptionId)
      .run();
  } else {
    await db
      .prepare(`UPDATE subscriptions SET status = ?, updated_at = datetime('now') WHERE subscription_id = ?`)
      .bind(status, subscriptionId)
      .run();
  }
}

async function handleSubscriptionCanceled(db, data) {
  const subscriptionId = data.id;

  await db
    .prepare(`UPDATE subscriptions SET status = 'canceled', updated_at = datetime('now') WHERE subscription_id = ?`)
    .bind(subscriptionId)
    .run();
}

