-- Subscriptions & API keys
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id TEXT NOT NULL UNIQUE,
  subscription_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'dev',
  period TEXT NOT NULL DEFAULT 'monthly',
  api_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_subscriptions_api_key ON subscriptions(api_key);
CREATE INDEX idx_subscriptions_customer_id ON subscriptions(customer_id);
CREATE INDEX idx_subscriptions_email ON subscriptions(email);

-- Monthly usage tracking
CREATE TABLE IF NOT EXISTS usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key TEXT NOT NULL,
  month TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  UNIQUE(api_key, month)
);

CREATE INDEX idx_usage_key_month ON usage(api_key, month);
