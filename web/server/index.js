const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.json());

// Raw body for webhook signature verification
app.use('/api/paddle/webhook', express.raw({ type: 'application/json' }));

// ===== Paddle Webhook =====
// TODO: Set your Paddle webhook secret key
const PADDLE_WEBHOOK_SECRET = process.env.PADDLE_WEBHOOK_SECRET || '';

function verifyPaddleWebhook(req) {
  if (!PADDLE_WEBHOOK_SECRET) return true; // Skip in dev

  const signature = req.headers['paddle-signature'];
  if (!signature) return false;

  // Parse signature header: ts=xxx;h1=xxx
  const parts = {};
  signature.split(';').forEach((part) => {
    const [key, value] = part.split('=');
    parts[key] = value;
  });

  const ts = parts['ts'];
  const h1 = parts['h1'];
  if (!ts || !h1) return false;

  // Build signed payload
  const payload = `${ts}:${req.body}`;
  const expected = crypto
    .createHmac('sha256', PADDLE_WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');

  return crypto.timingSafeEqual(Buffer.from(h1), Buffer.from(expected));
}

app.post('/api/paddle/webhook', (req, res) => {
  // Verify signature
  if (!verifyPaddleWebhook(req)) {
    console.error('Invalid webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = JSON.parse(req.body.toString());
  console.log(`[Paddle Webhook] ${event.event_type}`, event.data?.id);

  switch (event.event_type) {
    case 'subscription.created':
      handleSubscriptionCreated(event.data);
      break;
    case 'subscription.updated':
      handleSubscriptionUpdated(event.data);
      break;
    case 'subscription.canceled':
      handleSubscriptionCanceled(event.data);
      break;
    case 'transaction.completed':
      handleTransactionCompleted(event.data);
      break;
    default:
      console.log(`Unhandled event: ${event.event_type}`);
  }

  res.json({ received: true });
});

// ===== Webhook Handlers =====

function handleSubscriptionCreated(data) {
  const customerId = data.customer_id;
  const plan = data.custom_data?.plan || 'unknown';
  const apiKey = generateApiKey();

  console.log(`[New Subscription] Customer: ${customerId}, Plan: ${plan}`);
  console.log(`[API Key Generated] ${apiKey}`);

  // TODO: Save to database
  // db.users.create({ customerId, plan, apiKey, status: 'active' });

  // TODO: Send API key via email
  // email.send(data.customer.email, { apiKey, plan });
}

function handleSubscriptionUpdated(data) {
  const customerId = data.customer_id;
  const status = data.status;

  console.log(`[Subscription Updated] Customer: ${customerId}, Status: ${status}`);

  // TODO: Update database
  // db.users.update({ customerId }, { status, plan: data.custom_data?.plan });
}

function handleSubscriptionCanceled(data) {
  const customerId = data.customer_id;

  console.log(`[Subscription Canceled] Customer: ${customerId}`);

  // TODO: Revoke API key, update database
  // db.users.update({ customerId }, { status: 'canceled' });
}

function handleTransactionCompleted(data) {
  console.log(`[Transaction Completed] ID: ${data.id}, Amount: ${data.details?.totals?.total}`);
}

// ===== API Key Generation =====
function generateApiKey() {
  const prefix = 'cc_live_';
  const key = crypto.randomBytes(24).toString('base64url');
  return prefix + key;
}

// ===== API Key Validation Endpoint =====
// MCP server calls this to verify API keys
app.post('/api/validate-key', (req, res) => {
  const { apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({ valid: false, error: 'API key required' });
  }

  // TODO: Lookup in database
  // const user = db.users.findOne({ apiKey, status: 'active' });
  // if (!user) return res.status(401).json({ valid: false });

  // Placeholder response
  res.json({
    valid: true,
    plan: 'dev',
    remaining: 185, // AI analysis calls remaining this month
    limit: 200,
  });
});

// ===== Usage Tracking Endpoint =====
app.post('/api/usage', (req, res) => {
  const { apiKey, action } = req.body;

  // TODO: Increment usage counter in database
  // db.usage.increment({ apiKey, action, month: currentMonth() });

  console.log(`[Usage] Key: ${apiKey?.slice(0, 12)}..., Action: ${action}`);
  res.json({ recorded: true });
});

// ===== Success Page =====
app.get('/success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="ko">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>구독 완료 — cleaner-code</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
      <style>
        body {
          font-family: 'Inter', sans-serif;
          background: #0a0a0f; color: #e4e4ed;
          display: flex; justify-content: center; align-items: center;
          min-height: 100vh; margin: 0;
        }
        .card {
          background: #12121a; border: 1px solid #1e1e2e;
          border-radius: 16px; padding: 48px; text-align: center;
          max-width: 480px;
        }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { font-size: 28px; margin-bottom: 12px; }
        p { color: #8888a0; font-size: 15px; line-height: 1.7; margin-bottom: 24px; }
        .btn {
          display: inline-block; padding: 12px 24px;
          background: #6c5ce7; color: #fff;
          border-radius: 8px; font-weight: 600;
          text-decoration: none; font-size: 14px;
        }
        .btn:hover { background: #7c6cf7; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="icon">&#x2705;</div>
        <h1>구독이 완료되었습니다!</h1>
        <p>
          API 키가 등록된 이메일로 발송됩니다.<br>
          몇 분 내로 도착하지 않으면 스팸 폴더를 확인해주세요.
        </p>
        <a href="/" class="btn">홈으로 돌아가기</a>
      </div>
    </body>
    </html>
  `);
});

// ===== SPA Fallback =====
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`cleaner-code web server running at http://localhost:${PORT}`);
});
