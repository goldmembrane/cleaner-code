// Cloudflare Pages Function: POST /api/paddle/webhook

export async function onRequestPost(context) {
  const { request, env } = context;

  // Verify Paddle webhook signature
  const signature = request.headers.get('paddle-signature');
  const rawBody = await request.text();

  if (env.PADDLE_WEBHOOK_SECRET && signature) {
    const valid = await verifySignature(rawBody, signature, env.PADDLE_WEBHOOK_SECRET);
    if (!valid) {
      return new Response(JSON.stringify({ error: 'Invalid signature' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  const event = JSON.parse(rawBody);
  console.log(`[Paddle Webhook] ${event.event_type}`, event.data?.id);

  switch (event.event_type) {
    case 'subscription.created':
      await handleSubscriptionCreated(event.data, env);
      break;
    case 'subscription.updated':
      console.log(`[Updated] Customer: ${event.data.customer_id}, Status: ${event.data.status}`);
      break;
    case 'subscription.canceled':
      console.log(`[Canceled] Customer: ${event.data.customer_id}`);
      break;
    case 'transaction.completed':
      console.log(`[Transaction] ID: ${event.data.id}`);
      break;
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

async function handleSubscriptionCreated(data, env) {
  const apiKey = 'cc_live_' + generateKey();
  console.log(`[New Sub] Customer: ${data.customer_id}, Key: ${apiKey}`);

  // TODO: Store in KV or D1 database
  // await env.USERS_KV.put(`customer:${data.customer_id}`, JSON.stringify({
  //   apiKey,
  //   plan: data.custom_data?.plan,
  //   status: 'active',
  //   createdAt: new Date().toISOString(),
  // }));
}

function generateKey() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function verifySignature(payload, signature, secret) {
  const parts = {};
  signature.split(';').forEach((part) => {
    const [key, value] = part.split('=');
    parts[key] = value;
  });

  const ts = parts['ts'];
  const h1 = parts['h1'];
  if (!ts || !h1) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signed = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${ts}:${payload}`)
  );

  const expected = Array.from(new Uint8Array(signed))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return expected === h1;
}
