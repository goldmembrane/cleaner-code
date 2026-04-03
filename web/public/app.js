// ===== Paddle Configuration =====
const PADDLE_CONFIG = {
  clientToken: 'live_8d1ecb79cacb43b9b3f240d7240',

  prices: {
    dev: {
      monthly: 'pri_01kn8p5gw6h4r2xabpxsxj9fqv',    // $9/month
      yearly: 'pri_01kn8p62rxr3zkbfp74w0s42zx',      // $7/month billed yearly ($84/year)
    },
    team: {
      monthly: 'pri_01kn8p8f9zh60q99h4me0fw0mz',   // $29/user/month
      yearly: 'pri_01kn8p96an9z0b55a012grnay4',     // $23/user/month billed yearly ($276/year)
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
  sessionStorage.setItem('checkout_customer_id', data?.customer?.id || '');
  sessionStorage.setItem('checkout_transaction_id', data?.transaction_id || '');
  window.location.href = '/success.html';
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
