// ===== Paddle Configuration =====
// TODO: Replace with your actual Paddle credentials
const PADDLE_CONFIG = {
  // Paddle environment: 'sandbox' for testing, remove for production
  environment: 'sandbox',

  // Your Paddle client-side token (from Paddle Dashboard > Developer Tools > Authentication)
  clientToken: 'test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',

  // Paddle Price IDs (create these in Paddle Dashboard > Catalog > Prices)
  prices: {
    dev: {
      monthly: 'pri_dev_monthly_placeholder',    // $9/month
      yearly: 'pri_dev_yearly_placeholder',      // $7/month billed yearly ($84/year)
    },
    team: {
      monthly: 'pri_team_monthly_placeholder',   // $29/user/month
      yearly: 'pri_team_yearly_placeholder',     // $23/user/month billed yearly ($276/year)
    },
  },
};

// ===== Initialize Paddle =====
function initPaddle() {
  if (typeof Paddle === 'undefined') {
    console.warn('Paddle.js not loaded');
    return;
  }

  try {
    Paddle.Initialize({
      token: PADDLE_CONFIG.clientToken,
      environment: PADDLE_CONFIG.environment, // Remove this line for production
      eventCallback: handlePaddleEvent,
    });
  } catch (e) {
    console.warn('Paddle initialization failed (set valid credentials):', e.message);
  }
}

// ===== Paddle Event Handler =====
function handlePaddleEvent(event) {
  switch (event.name) {
    case 'checkout.completed':
      handleCheckoutComplete(event.data);
      break;
    case 'checkout.closed':
      console.log('Checkout closed');
      break;
    case 'checkout.error':
      showToast('An error occurred during checkout. Please try again.', 'error');
      break;
  }
}

// ===== Checkout Handler =====
function handleCheckout(plan) {
  const period = document.querySelector('.toggle-btn.active')?.dataset.period || 'monthly';
  const priceId = PADDLE_CONFIG.prices[plan]?.[period];

  if (!priceId || priceId.includes('placeholder')) {
    showToast('Paddle configuration required. Please set valid Price IDs.', 'error');
    return;
  }

  Paddle.Checkout.open({
    items: [{ priceId, quantity: 1 }],
    settings: {
      displayMode: 'overlay',
      theme: 'dark',
      locale: 'ko',
      successUrl: window.location.origin + '/success',
      allowLogout: true,
    },
    customData: {
      plan,
      period,
    },
  });
}

// ===== Free Plan Handler =====
function handleFree() {
  showToast('Install cleaner-code from GitHub and start for free!', 'success');
  setTimeout(() => {
    window.open('https://github.com/goldmembrane/cleaner-code', '_blank');
  }, 1500);
}

// ===== Checkout Complete =====
function handleCheckoutComplete(data) {
  showToast('Subscription complete! Your API key will be sent via email.', 'success');

  // Track conversion (optional analytics)
  console.log('Checkout completed:', {
    transactionId: data?.transaction_id,
    plan: data?.custom_data?.plan,
  });
}

// ===== Billing Period Toggle =====
function initToggle() {
  const wrap = document.querySelector('.toggle-wrap');
  const priceAmounts = document.querySelectorAll('.price-amount[data-monthly]');
  const annualNotes = document.querySelectorAll('.price-annual-note[data-monthly]');

  wrap.addEventListener('click', (e) => {
    const btn = e.target.closest('.toggle-btn');
    if (!btn) return;

    wrap.querySelectorAll('.toggle-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');

    const period = btn.dataset.period;
    priceAmounts.forEach((el) => {
      el.textContent = el.dataset[period];
    });
    annualNotes.forEach((el) => {
      el.textContent = el.dataset[period] || '';
    });
  });
}

// ===== Toast Notification =====
function showToast(message, type = 'info') {
  // Remove existing toast
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => {
    toast.classList.add('show');
  });

  // Auto-remove
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ===== Login Button =====
function initLogin() {
  const loginBtn = document.getElementById('loginBtn');
  if (loginBtn) {
    loginBtn.addEventListener('click', (e) => {
      e.preventDefault();
      showToast('Sign-in feature coming soon.', 'info');
    });
  }
}

// ===== Smooth scroll for nav links =====
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener('click', (e) => {
      const targetId = anchor.getAttribute('href');
      if (targetId === '#') return;
      e.preventDefault();
      const target = document.querySelector(targetId);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
}

// ===== Init =====
document.addEventListener('DOMContentLoaded', () => {
  initToggle();
  initLogin();
  initSmoothScroll();
  initPaddle();
});
