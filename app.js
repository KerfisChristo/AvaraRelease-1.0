// ---- Shared Avara frontend utilities ----

const app = {
  apiBase: (location.port && location.port !== '3000') ? 'http://localhost:3000' : '',
  user: null,
  socket: null,

  init() {
    this.setupDarkMode();
    this.setupNotificationBell();
    this.setupKeyboardShortcuts();
  },

  apiFetch(path, opts = {}) {
    const fetchOpts = { ...opts };
    fetchOpts.credentials = 'include';
    return fetch(this.apiBase + path, fetchOpts);
  },

  async parseJson(response) {
    const text = await response.text();
    return text ? JSON.parse(text) : {};
  },

  async ensureLoggedIn() {
    try {
      const response = await this.apiFetch('/api/admin/session');
      const payload = await this.parseJson(response);
      if (!payload.loggedIn) {
        window.location.href = this.apiBase + '/Login.html';
        return null;
      }
      this.user = payload.user;
      return payload.user;
    } catch (error) {
      window.location.href = this.apiBase + '/Login.html';
      return null;
    }
  },

  async logout() {
    try {
      await this.apiFetch('/api/admin/logout', { method: 'POST' });
    } catch (e) {}
    window.location.href = this.apiBase + '/Home.html';
  },

  initials(name) {
    return (name || '?').split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
  },

  formatDate(value) {
    if (!value) return '';
    return new Date(value).toLocaleString('is-IS', { dateStyle: 'medium', timeStyle: 'short' });
  },

  formatTime(value) {
    if (!value) return '';
    return new Date(value).toLocaleTimeString('is-IS', { hour: '2-digit', minute: '2-digit' });
  },

  // ---- Toast notifications ----
  toast(message, type = 'success', duration = 3000) {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:10px;';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.style.cssText = `
      padding:14px 20px;border-radius:12px;font-size:14px;font-weight:600;
      box-shadow:0 8px 24px rgba(0,0,0,0.15);animation:toastIn 0.3s ease;
      background:${type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#10b981'};color:white;
      display:flex;align-items:center;gap:8px;max-width:380px;
    `;
    const icon = type === 'error' ? '❌' : type === 'warning' ? '⚠️' : '✅';
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.transition = 'opacity 0.3s, transform 0.3s';
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  // ---- Dark mode ----
  async setupDarkMode() {
    try {
      const saved = localStorage.getItem('avara_dark_mode');
      if (saved !== null) {
        document.documentElement.classList.toggle('dark', saved === '1');
        this.updateDarkModeIcon();
        return;
      }

      const response = await this.apiFetch('/api/prefs');
      const payload = await this.parseJson(response);
      if (payload.ok) {
        document.documentElement.classList.toggle('dark', payload.prefs.darkMode === 1);
        this.updateDarkModeIcon();
      }
    } catch (e) {}
  },

  updateDarkModeIcon() {
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) {
      toggle.textContent = document.documentElement.classList.contains('dark') ? '☀️' : '🌙';
    }
  },

  async toggleDarkMode() {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('avara_dark_mode', isDark ? '1' : '0');
    this.updateDarkModeIcon();
    try {
      await this.apiFetch('/api/prefs', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ darkMode: isDark ? 1 : 0 })
      });
    } catch (e) {}
    return isDark;
  },

  // ---- Notifications bell ----
  async setupNotificationBell() {
    const bell = document.getElementById('notificationBell');
    if (!bell) return;

    const load = async () => {
      try {
        const response = await this.apiFetch('/api/notifications');
        const payload = await this.parseJson(response);
        if (!payload.ok) return;

        const badge = bell.querySelector('.notification-badge');
        if (payload.unreadCount > 0) {
          bell.classList.add('has-unread');
          if (badge) badge.textContent = payload.unreadCount > 99 ? '99+' : payload.unreadCount;
        } else {
          bell.classList.remove('has-unread');
          if (badge) badge.remove();
        }
      } catch (e) {}
    };

    await load();
    setInterval(load, 30000);

    bell.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const panel = document.getElementById('notificationPanel');
      if (panel && panel.classList.contains('open')) {
        panel.classList.remove('open');
        return;
      }

      try {
        const response = await this.apiFetch('/api/notifications');
        const payload = await this.parseJson(response);
        if (!payload.ok) return;

        await this.apiFetch('/api/notifications/read', { method: 'POST' });

        let panelEl = document.getElementById('notificationPanel');
        if (!panelEl) {
          panelEl = document.createElement('div');
          panelEl.id = 'notificationPanel';
          panelEl.style.cssText = `
            position:fixed;top:70px;right:24px;width:380px;max-height:500px;overflow-y:auto;
            background:var(--white, white);border-radius:16px;box-shadow:0 24px 60px rgba(0,0,0,0.2);
            border:1px solid rgba(15,23,42,0.1);z-index:9999;
          `;
          document.body.appendChild(panelEl);
        }

        panelEl.innerHTML = `
          <div style="padding:16px 20px;border-bottom:1px solid rgba(15,23,42,0.08);font-weight:800;font-size:16px;color:var(--ink-900, #0f172a);">
            🔔 Tilkynningar
          </div>
          <div style="padding:8px;">
            ${payload.notifications.length === 0
              ? '<p style="padding:20px;text-align:center;color:var(--ink-500, #64748b);font-size:14px;">Engar tilkynningar</p>'
              : payload.notifications.slice(0, 20).map(n => `
                <a href="${n.link || '#'}" style="display:block;padding:12px 14px;border-radius:10px;text-decoration:none;color:var(--ink-900, #0f172a);transition:background 0.2s;">
                  <div style="font-weight:700;font-size:14px;">${n.title}</div>
                  ${n.body ? `<div style="font-size:13px;color:var(--ink-500, #64748b);margin-top:2px;">${n.body}</div>` : ''}
                  <div style="font-size:11px;color:var(--ink-300, #94a3b8);margin-top:4px;">${new Date(n.created_at).toLocaleString('is-IS', { dateStyle: 'short', timeStyle: 'short' })}</div>
                </a>
              `).join('')}
          </div>
        `;
        panelEl.classList.add('open');
      } catch (e) {}
    });

    document.addEventListener('click', (e) => {
      const panel = document.getElementById('notificationPanel');
      if (panel && !panel.contains(e.target) && !bell.contains(e.target)) {
        panel.remove();
      }
    });
  },

  // ---- Keyboard shortcuts ----
  setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const input = document.getElementById('globalSearchInput');
        if (input) {
          input.focus();
          input.select();
        }
      }
      if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        const search = document.querySelector('.search-input, input[type="search"]');
        if (search) search.focus();
      }
    });
  },

  // ---- Skeleton loader ----
  skeleton(container, count = 3) {
    if (!container) return;
    container.innerHTML = Array.from({ length: count }, () => `
      <div class="skeleton-line" style="height:16px;border-radius:8px;background:linear-gradient(90deg,#e5e7eb 25%,#f3f4f6 50%,#e5e7eb 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;margin-bottom:12px;"></div>
    `).join('');
  },

  // ---- Socket.io connection ----
  connectSocket() {
    if (!this.user) return;
    if (window.io) {
      this.socket = io(this.apiBase || window.location.origin, {
        auth: {
          userId: this.user.id,
          userName: this.user.name || this.user.email
        }
      });
      this.socket.on('connect', () => {
        console.log('Socket connected');
      });
    }
  },

  escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }
};

// Add shimmer animation globally
const style = document.createElement('style');
style.textContent = `
  @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
  @keyframes toastIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
  .notification-badge {
    position:absolute;top:-4px;right:-4px;background:#ef4444;color:white;font-size:11px;font-weight:700;
    border-radius:999px;min-width:18px;height:18px;display:flex;align-items:center;justify-content:center;
    padding:0 4px;box-shadow:0 2px 4px rgba(0,0,0,0.2);
  }
`;
document.head.appendChild(style);

window.app = app;