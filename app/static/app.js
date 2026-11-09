const CSRF = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeHref(url) {
  if (!url) return '#';
  const s = String(url).trim().toLowerCase();
  if (s.startsWith('http://') || s.startsWith('https://')) return esc(url);
  return '#';
}

function icon(name) {
  return `<svg class="icon" aria-hidden="true"><use href="/static/icons.svg#${name}"></use></svg>`;
}

function capitalize(value) {
  const text = String(value || '');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function severityKey(severity) {
  return ['critical', 'high', 'medium', 'low'].includes(severity) ? severity : 'unknown';
}

function severityLabel(severity) {
  const key = severityKey(severity);
  return `<span class="sev-label sev-${key}">${capitalize(key)}</span>`;
}

function timeAgo(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
  return d.toLocaleDateString();
}

function formatDateTime(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  const date = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  return `${date}, ${time}`;
}

// Theme
const themeBtn = document.getElementById('themeBtn');

function renderThemeButton() {
  if (!themeBtn) return;
  const isLight = document.documentElement.classList.contains('light');
  themeBtn.innerHTML = icon(isLight ? 'moon' : 'sun');
  themeBtn.title = isLight ? 'Dark theme' : 'Light theme';
}

if (themeBtn) {
  renderThemeButton();
  themeBtn.addEventListener('click', () => {
    const isLight = document.documentElement.classList.toggle('light');
    try { localStorage.setItem('theme', isLight ? 'light' : 'dark'); } catch (e) {}
    renderThemeButton();
  });
}

// Mobile navigation
const menuToggle = document.getElementById('menuToggle');
const sidebarBody = document.getElementById('sidebarBody');

function setMenuOpen(open) {
  if (!menuToggle || !sidebarBody) return;
  sidebarBody.classList.toggle('open', open);
  menuToggle.setAttribute('aria-expanded', String(open));
  menuToggle.innerHTML = icon(open ? 'x' : 'menu');
}

if (menuToggle) {
  menuToggle.addEventListener('click', () => setMenuOpen(!sidebarBody.classList.contains('open')));
  document.addEventListener('click', event => {
    if (!event.target.closest('.sidebar')) setMenuOpen(false);
  });
}

// Destructive actions ask first
document.addEventListener('submit', event => {
  const message = event.target.dataset?.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
