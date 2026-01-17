bash -c '
#!/bin/bash
set -e

PTERO_DIR="/var/www/pterodactyl"
TIMESTAMP=$(date +%s)

cd "$PTERO_DIR"

echo "════════════════════════════════════════════════════════════"
echo "  NOOBEE GLASS ULTRA — Full System Theme Deployment"
echo "════════════════════════════════════════════════════════════"
echo ""

# ============================================
# STEP 1: BACKUP EXISTING FILES
# ============================================
echo "[1/6] Creating backups..."

mkdir -p storage/theme-backups

[ -f "resources/views/layouts/admin.blade.php" ] && \
  cp "resources/views/layouts/admin.blade.php" "storage/theme-backups/admin.blade.php.$TIMESTAMP"

[ -f "resources/views/templates/wrapper.blade.php" ] && \
  cp "resources/views/templates/wrapper.blade.php" "storage/theme-backups/wrapper.blade.php.$TIMESTAMP"

[ -f "resources/views/layouts/auth.blade.php" ] && \
  cp "resources/views/layouts/auth.blade.php" "storage/theme-backups/auth.blade.php.$TIMESTAMP"

[ -f "public/themes/noobee-glass.css" ] && \
  cp "public/themes/noobee-glass.css" "storage/theme-backups/noobee-glass.css.$TIMESTAMP"

echo "✓ Backups saved to storage/theme-backups/"

# ============================================
# STEP 2: CREATE GLASSMORPHISM CSS
# ============================================
echo "[2/6] Creating glassmorphism CSS..."

mkdir -p public/themes

cat > public/themes/noobee-glass.css << "CSSEOF"
/* ═══════════════════════════════════════════════════════════════
   NOOBEE GLASS ULTRA THEME
   Modern Glassmorphism Design System for Pterodactyl Panel
   Coverage: Admin + User + Auth + All Server Pages
   Design Reference: Linear, Vercel, Stripe, Apple Glass UI
   ═══════════════════════════════════════════════════════════════ */

@import url("https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&display=swap");

/* ═══════════════════════════════════════════════════════════════
   CSS VARIABLES — Design System Foundation
   ═══════════════════════════════════════════════════════════════ */
:root {
  /* Base Colors */
  --glass-dark-base: #0a0e1a;
  --glass-dark-surface: #0f172a;
  --glass-dark-elevated: #1e293b;
  
  /* Glass Layers */
  --glass-bg-primary: rgba(15, 23, 42, 0.80);
  --glass-bg-secondary: rgba(30, 41, 59, 0.75);
  --glass-bg-tertiary: rgba(51, 65, 85, 0.70);
  --glass-bg-elevated: rgba(71, 85, 105, 0.65);
  
  /* Text */
  --text-white: #ffffff;
  --text-primary: #f8fafc;
  --text-secondary: #e2e8f0;
  --text-muted: #94a3b8;
  --text-subtle: #64748b;
  
  /* Accents */
  --accent-primary: #3b82f6;
  --accent-secondary: #60a5fa;
  --accent-cyan: #06b6d4;
  --accent-emerald: #10b981;
  --accent-red: #ef4444;
  --accent-amber: #f59e0b;
  
  /* Borders */
  --border-glass: rgba(148, 163, 184, 0.15);
  --border-subtle: rgba(148, 163, 184, 0.10);
  --border-focus: rgba(59, 130, 246, 0.40);
  
  /* Shadows */
  --shadow-glass-sm: 0 2px 8px rgba(0, 0, 0, 0.12), 0 0 0 1px rgba(255, 255, 255, 0.05);
  --shadow-glass-md: 0 4px 16px rgba(0, 0, 0, 0.20), 0 0 0 1px rgba(255, 255, 255, 0.06);
  --shadow-glass-lg: 0 8px 32px rgba(0, 0, 0, 0.28), 0 0 0 1px rgba(255, 255, 255, 0.08);
  --shadow-glow: 0 0 24px rgba(59, 130, 246, 0.20);
  
  /* Transitions */
  --transition-base: 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  --transition-smooth: 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

/* ═══════════════════════════════════════════════════════════════
   GLOBAL FOUNDATION
   ═══════════════════════════════════════════════════════════════ */
*,
*::before,
*::after {
  box-sizing: border-box;
}

html {
  overflow-x: hidden;
  overflow-y: auto;
  scroll-behavior: smooth;
}

html,
body {
  margin: 0;
  padding: 0;
  font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background: radial-gradient(ellipse at top, #1e293b 0%, #0f172a 50%, #020617 100%) fixed !important;
  color: var(--text-primary) !important;
  line-height: 1.6;
}

body {
  overflow-x: hidden;
  overflow-y: auto !important;
  min-height: 100vh;
}

/* Force override body classes */
body.bg-neutral-50,
body.bg-neutral-900,
body.bg-gray-50,
body.bg-gray-900,
body.bg-zinc-900 {
  background: radial-gradient(ellipse at top, #1e293b 0%, #0f172a 50%, #020617 100%) fixed !important;
}

/* ═══════════════════════════════════════════════════════════════
   ADMIN PANEL — AdminLTE
   ═══════════════════════════════════════════════════════════════ */

/* Main Wrapper */
.wrapper {
  overflow: visible !important;
}

.content-wrapper,
.main-content {
  background: transparent !important;
  overflow-y: auto !important;
  overflow-x: hidden;
  padding: 20px;
}

/* Header & Navbar */
.main-header,
.navbar,
.navbar-static-top {
  background: var(--glass-bg-primary) !important;
  backdrop-filter: blur(16px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
  border-bottom: 1px solid var(--border-glass) !important;
  box-shadow: var(--shadow-glass-sm);
}

.navbar-nav > li > a,
.navbar-nav > li > button {
  color: var(--text-white) !important;
  font-weight: 500;
  transition: color var(--transition-base);
}

.navbar-nav > li > a:hover,
.navbar-nav > li > button:hover {
  color: var(--accent-secondary) !important;
  background: rgba(59, 130, 246, 0.1) !important;
}

/* Sidebar */
.main-sidebar {
  background: var(--glass-bg-primary) !important;
  backdrop-filter: blur(16px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
  border-right: 1px solid var(--border-glass) !important;
  box-shadow: var(--shadow-glass-sm);
}

.sidebar {
  overflow-y: auto !important;
  overflow-x: hidden;
  height: calc(100vh - 50px);
}

.sidebar-menu {
  padding: 8px;
}

.sidebar-menu > li > a {
  color: var(--text-secondary) !important;
  padding: 12px 16px;
  margin: 2px 0;
  border-radius: 10px;
  transition: all var(--transition-base);
  font-weight: 500;
}

.sidebar-menu > li > a:hover {
  background: var(--glass-bg-tertiary) !important;
  color: var(--text-white) !important;
  transform: translateX(2px);
}

.sidebar-menu > li.active > a,
.sidebar-menu > li.active > a:hover {
  background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary)) !important;
  color: var(--text-white) !important;
  box-shadow: var(--shadow-glow);
}

.sidebar-menu .treeview-menu {
  background: rgba(0, 0, 0, 0.15);
  border-radius: 8px;
  margin: 4px 8px;
}

.sidebar-menu .treeview-menu > li > a {
  color: var(--text-muted) !important;
  padding: 10px 16px 10px 32px;
  transition: all var(--transition-base);
}

.sidebar-menu .treeview-menu > li > a:hover {
  color: var(--text-white) !important;
  background: rgba(255, 255, 255, 0.05) !important;
}

/* ═══════════════════════════════════════════════════════════════
   USER PANEL — React + Tailwind
   ═══════════════════════════════════════════════════════════════ */

/* React Root */
#app,
#app > div,
[data-reactroot] {
  background: transparent !important;
  color: var(--text-primary) !important;
}

/* User Panel Navbar — Force White Text & Icons */
#app nav,
#app header,
nav[class*="sticky"],
header[class*="sticky"] {
  background: var(--glass-bg-primary) !important;
  backdrop-filter: blur(16px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
  border-bottom: 1px solid var(--border-glass) !important;
  box-shadow: var(--shadow-glass-sm);
}

#app nav *,
#app header *,
nav[class*="sticky"] *,
header[class*="sticky"] * {
  color: var(--text-white) !important;
}

/* Force SVG icons white */
#app nav svg,
#app header svg,
nav[class*="sticky"] svg,
header[class*="sticky"] svg {
  fill: currentColor !important;
  stroke: currentColor !important;
  color: var(--text-white) !important;
}

#app nav svg *,
#app header svg *,
nav[class*="sticky"] svg *,
header[class*="sticky"] svg * {
  fill: currentColor !important;
  stroke: currentColor !important;
}

/* ═══════════════════════════════════════════════════════════════
   CARDS & BOXES — Universal
   ═══════════════════════════════════════════════════════════════ */

.card,
.box,
.panel,
#app div.rounded-lg,
#app div.rounded-xl,
#app div.rounded-md,
#app div.rounded,
div[class*="rounded"].shadow,
div[class*="rounded"][class*="bg-neutral"],
div[class*="rounded"][class*="bg-gray"],
div[class*="rounded"][class*="bg-zinc"] {
  background: var(--glass-bg-secondary) !important;
  backdrop-filter: blur(12px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(12px) saturate(180%) !important;
  border: 1px solid var(--border-glass) !important;
  border-radius: 12px !important;
  box-shadow: var(--shadow-glass-md) !important;
  margin-bottom: 20px;
  overflow: hidden;
}

.card-header,
.box-header,
.panel-heading,
div[class*="rounded-t"] {
  background: var(--glass-bg-tertiary) !important;
  border-bottom: 1px solid var(--border-glass) !important;
  color: var(--text-white) !important;
  font-weight: 600;
  padding: 16px 20px;
  border-radius: 12px 12px 0 0 !important;
}

.card-body,
.box-body,
.panel-body {
  color: var(--text-secondary) !important;
  padding: 20px;
}

.card-footer,
.box-footer {
  background: rgba(0, 0, 0, 0.10) !important;
  border-top: 1px solid var(--border-subtle) !important;
  padding: 16px 20px;
}

/* ═══════════════════════════════════════════════════════════════
   OVERRIDE TAILWIND BACKGROUNDS (Safe & Specific)
   ═══════════════════════════════════════════════════════════════ */

#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-neutral-700"],
#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-neutral-800"],
#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-neutral-900"],
#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-gray-700"],
#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-gray-800"],
#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-gray-900"],
#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-zinc-800"],
#app :where(div, section, main, article):not(button):not([class*="chart"]):not([role="progressbar"])[class*="bg-zinc-900"] {
  background-color: var(--glass-bg-secondary) !important;
  backdrop-filter: blur(10px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(10px) saturate(180%) !important;
  border-color: var(--border-glass) !important;
}

#app :where(div, section, header):not(button)[class*="bg-neutral-600"],
#app :where(div, section, header):not(button)[class*="bg-gray-600"] {
  background-color: var(--glass-bg-tertiary) !important;
  backdrop-filter: blur(10px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(10px) saturate(180%) !important;
}

/* ═══════════════════════════════════════════════════════════════
   AUTH PAGES — Login, Register, Reset
   ═══════════════════════════════════════════════════════════════ */

body.login,
body.auth,
body.register,
.auth-container {
  background: radial-gradient(ellipse at top, #1e293b 0%, #0f172a 50%, #020617 100%) fixed !important;
}

.login-box,
.register-box,
.auth-card,
div.max-w-md.mx-auto,
div.max-w-lg.mx-auto {
  background: var(--glass-bg-secondary) !important;
  backdrop-filter: blur(20px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
  border: 1px solid var(--border-glass) !important;
  border-radius: 16px !important;
  box-shadow: var(--shadow-glass-lg), var(--shadow-glow) !important;
}

.login-box-msg,
.register-box-msg,
.auth-header {
  color: var(--text-white) !important;
  font-weight: 600;
  font-size: 24px;
  margin-bottom: 24px;
}

/* ═══════════════════════════════════════════════════════════════
   TABLES
   ═══════════════════════════════════════════════════════════════ */

.table,
#app table {
  color: var(--text-secondary) !important;
  border-collapse: separate;
  border-spacing: 0;
}

.table thead th,
#app table thead th {
  background: var(--glass-bg-tertiary) !important;
  color: var(--text-white) !important;
  font-weight: 600;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 2px solid var(--border-glass) !important;
  padding: 14px 16px;
}

.table tbody td,
#app table tbody td {
  border-color: var(--border-subtle) !important;
  padding: 14px 16px;
  vertical-align: middle;
}

.table tbody tr,
#app table tbody tr {
  transition: background-color var(--transition-base);
}

.table tbody tr:hover,
#app table tbody tr:hover {
  background: rgba(59, 130, 246, 0.08) !important;
}

.table-striped tbody tr:nth-of-type(odd) {
  background: rgba(71, 85, 105, 0.15) !important;
}

/* ═══════════════════════════════════════════════════════════════
   FORMS
   ═══════════════════════════════════════════════════════════════ */

.form-control,
.form-select,
select,
textarea,
input[type="text"],
input[type="email"],
input[type="password"],
input[type="number"],
input[type="search"],
input[type="url"],
input[type="date"],
input[type="time"] {
  background: var(--glass-bg-tertiary) !important;
  border: 1px solid var(--border-glass) !important;
  color: var(--text-white) !important;
  border-radius: 10px !important;
  padding: 10px 14px !important;
  font-size: 14px;
  transition: all var(--transition-base);
  font-weight: 400;
}

.form-control:focus,
.form-select:focus,
select:focus,
textarea:focus,
input:focus {
  background: var(--glass-bg-elevated) !important;
  border-color: var(--accent-primary) !important;
  box-shadow: 0 0 0 4px var(--border-focus), var(--shadow-glass-sm) !important;
  outline: none !important;
}

.form-control::placeholder,
input::placeholder,
textarea::placeholder {
  color: var(--text-muted) !important;
  opacity: 0.7;
}

.form-group label,
label {
  color: var(--text-secondary) !important;
  font-weight: 500;
  font-size: 14px;
  margin-bottom: 8px;
  display: block;
}

/* ═══════════════════════════════════════════════════════════════
   BUTTONS — Universal System
   ═══════════════════════════════════════════════════════════════ */

.btn,
button:not(.close):not([class*="xterm"]),
a.btn {
  padding: 10px 18px !important;
  border-radius: 10px !important;
  font-weight: 500;
  font-size: 14px;
  line-height: 1.5;
  transition: all var(--transition-base);
  border: 1px solid transparent;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  white-space: nowrap;
}

.btn:active,
button:active {
  transform: none !important;
  animation: none !important;
}

/* Primary */
.btn-primary,
button.bg-blue-600,
button.bg-blue-500 {
  background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary)) !important;
  border: none !important;
  color: var(--text-white) !important;
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.25);
}

.btn-primary:hover,
button.bg-blue-600:hover,
button.bg-blue-500:hover {
  background: linear-gradient(135deg, #4f96ff, #60a5fa) !important;
  box-shadow: 0 6px 20px rgba(59, 130, 246, 0.35), var(--shadow-glow) !important;
  transform: translateY(-1px);
}

/* Success */
.btn-success,
button.bg-green-600,
button.bg-green-500 {
  background: linear-gradient(135deg, #059669, var(--accent-emerald)) !important;
  color: var(--text-white) !important;
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.25);
}

.btn-success:hover,
button.bg-green-600:hover,
button.bg-green-500:hover {
  background: linear-gradient(135deg, #10b981, #34d399) !important;
  box-shadow: 0 6px 20px rgba(16, 185, 129, 0.35) !important;
  transform: translateY(-1px);
}

/* Danger */
.btn-danger,
button.bg-red-600,
button.bg-red-500 {
  background: linear-gradient(135deg, #dc2626, var(--accent-red)) !important;
  color: var(--text-white) !important;
  box-shadow: 0 4px 12px rgba(239, 68, 68, 0.25);
}

.btn-danger:hover,
button.bg-red-600:hover,
button.bg-red-500:hover {
  background: linear-gradient(135deg, #ef4444, #f87171) !important;
  box-shadow: 0 6px 20px rgba(239, 68, 68, 0.35) !important;
  transform: translateY(-1px);
}

/* Warning */
.btn-warning,
button.bg-yellow-600,
button.bg-yellow-500,
button.bg-amber-500 {
  background: linear-gradient(135deg, #d97706, var(--accent-amber)) !important;
  color: var(--text-white) !important;
  box-shadow: 0 4px 12px rgba(245, 158, 11, 0.25);
}

.btn-warning:hover,
button.bg-yellow-600:hover,
button.bg-yellow-500:hover,
button.bg-amber-500:hover {
  background: linear-gradient(135deg, #f59e0b, #fbbf24) !important;
  box-shadow: 0 6px 20px rgba(245, 158, 11, 0.35) !important;
  transform: translateY(-1px);
}

/* Secondary / Default */
.btn-secondary,
.btn-default,
button.bg-neutral-600,
button.bg-neutral-700,
button.bg-gray-600,
button.bg-gray-700 {
  background: var(--glass-bg-tertiary) !important;
  backdrop-filter: blur(8px) !important;
  -webkit-backdrop-filter: blur(8px) !important;
  border: 1px solid var(--border-glass) !important;
  color: var(--text-white) !important;
}

.btn-secondary:hover,
.btn-default:hover,
button.bg-neutral-600:hover,
button.bg-neutral-700:hover,
button.bg-gray-600:hover,
button.bg-gray-700:hover {
  background: var(--glass-bg-elevated) !important;
  border-color: var(--border-subtle) !important;
  transform: translateY(-1px);
}

/* ═══════════════════════════════════════════════════════════════
   CONSOLE / TERMINAL
   ═══════════════════════════════════════════════════════════════ */

.terminal,
.xterm,
.xterm-viewport,
.xterm-screen,
#app div[class*="console"],
#app .terminal {
  background: rgba(0, 0, 0, 0.95) !important;
  border: 1px solid var(--border-glass) !important;
  border-radius: 12px !important;
  box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.3);
}

/* Code blocks */
pre,
code {
  background: var(--glass-bg-tertiary) !important;
  border: 1px solid var(--border-subtle) !important;
  border-radius: 8px !important;
  color: var(--text-primary) !important;
  padding: 4px 8px;
  font-family: "IBM Plex Mono", "Fira Code", "Courier New", monospace;
}

pre {
  padding: 16px !important;
  overflow-x: auto;
}

/* ═══════════════════════════════════════════════════════════════
   MODALS & DIALOGS
   ═══════════════════════════════════════════════════════════════ */

.modal-content,
#app div[role="dialog"] > div:first-child,
div[class*="modal"] {
  background: var(--glass-bg-secondary) !important;
  backdrop-filter: blur(24px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
  border: 1px solid var(--border-glass) !important;
  border-radius: 16px !important;
  box-shadow: var(--shadow-glass-lg), var(--shadow-glow) !important;
}

.modal-header {
  background: var(--glass-bg-tertiary) !important;
  border-bottom: 1px solid var(--border-glass) !important;
  color: var(--text-white) !important;
  padding: 20px 24px;
  border-radius: 16px 16px 0 0 !important;
}

.modal-body {
  color: var(--text-secondary) !important;
  padding: 24px;
}

.modal-footer {
  background: rgba(0, 0, 0, 0.10) !important;
  border-top: 1px solid var(--border-subtle) !important;
  padding: 16px 24px;
  border-radius: 0 0 16px 16px !important;
}

.modal-backdrop {
  background: rgba(0, 0, 0, 0.75) !important;
  backdrop-filter: blur(4px);
}

/* ═══════════════════════════════════════════════════════════════
   ALERTS & NOTIFICATIONS
   ═══════════════════════════════════════════════════════════════ */

.alert,
#app div[role="alert"] {
  backdrop-filter: blur(12px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(12px) saturate(180%) !important;
  border-radius: 10px !important;
  border: 1px solid !important;
  padding: 14px 18px;
  font-weight: 500;
}

.alert-success {
  background: rgba(16, 185, 129, 0.15) !important;
  border-color: rgba(16, 185, 129, 0.40) !important;
  color: #6ee7b7 !important;
}

.alert-info {
  background: rgba(6, 182, 212, 0.15) !important;
  border-color: rgba(6, 182, 212, 0.40) !important;
  color: #67e8f9 !important;
}

.alert-warning {
  background: rgba(245, 158, 11, 0.15) !important;
  border-color: rgba(245, 158, 11, 0.40) !important;
  color: #fbbf24 !important;
}

.alert-danger {
  background: rgba(239, 68, 68, 0.15) !important;
  border-color: rgba(239, 68, 68, 0.40) !important;
  color: #fca5a5 !important;
}

/* ═══════════════════════════════════════════════════════════════
   BADGES & LABELS
   ═══════════════════════════════════════════════════════════════ */

.badge,
.label,
span[class*="badge"] {
  border-radius: 6px !important;
  padding: 4px 10px;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.025em;
}

/* ═══════════════════════════════════════════════════════════════
   PAGINATION
   ═══════════════════════════════════════════════════════════════ */

.pagination > li > a,
.pagination > li > span,
nav[role="navigation"] button {
  background: var(--glass-bg-tertiary) !important;
  border-color: var(--border-glass) !important;
  color: var(--text-secondary) !important;
  border-radius: 8px;
  padding: 8px 14px;
  transition: all var(--transition-base);
}

.pagination > li > a:hover,
nav[role="navigation"] button:hover {
  background: var(--glass-bg-elevated) !important;
  color: var(--text-white) !important;
  transform: translateY(-1px);
}

.pagination > .active > a,
nav[role="navigation"] button[aria-current="page"] {
  background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary)) !important;
  border-color: var(--accent-primary) !important;
  color: var(--text-white) !important;
  box-shadow: var(--shadow-glow);
}

/* ═══════════════════════════════════════════════════════════════
   DROPDOWNS
   ═══════════════════════════════════════════════════════════════ */

.dropdown-menu,
#app div[role="menu"] {
  background: var(--glass-bg-secondary) !important;
  backdrop-filter: blur(16px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
  border: 1px solid var(--border-glass) !important;
  border-radius: 10px !important;
  box-shadow: var(--shadow-glass-md);
  padding: 6px;
}

.dropdown-menu > li > a,
#app div[role="menuitem"] {
  color: var(--text-secondary) !important;
  padding: 10px 14px;
  border-radius: 6px;
  transition: all var(--transition-base);
}

.dropdown-menu > li > a:hover,
#app div[role="menuitem"]:hover {
  background: var(--glass-bg-tertiary) !important;
  color: var(--text-white) !important;
}

/* ═══════════════════════════════════════════════════════════════
   PROGRESS BARS
   ═══════════════════════════════════════════════════════════════ */

.progress,
#app div[class*="progress"] {
  background: var(--glass-bg-tertiary) !important;
  border-radius: 10px !important;
  height: 10px;
  overflow: hidden;
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.2);
}

.progress-bar,
#app div[role="progressbar"] > div {
  background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary)) !important;
  border-radius: 10px;
  transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);
}

/* ═══════════════════════════════════════════════════════════════
   TABS
   ═══════════════════════════════════════════════════════════════ */

.nav-tabs {
  border-bottom: 1px solid var(--border-glass) !important;
  margin-bottom: 20px;
}

.nav-tabs > li > a,
#app [role="tablist"] button {
  color: var(--text-muted) !important;
  border-radius: 10px 10px 0 0 !important;
  padding: 12px 20px;
  transition: all var(--transition-base);
  border: 1px solid transparent;
  font-weight: 500;
}

.nav-tabs > li > a:hover,
#app [role="tab"]:hover {
  background: var(--glass-bg-tertiary) !important;
  color: var(--text-white) !important;
}

.nav-tabs > li.active > a,
#app [role="tab"][aria-selected="true"] {
  background: var(--glass-bg-secondary) !important;
  border-color: var(--border-glass) var(--border-glass) transparent !important;
  color: var(--text-white) !important;
  font-weight: 600;
}

/* ═══════════════════════════════════════════════════════════════
   FOOTER
   ═══════════════════════════════════════════════════════════════ */

.main-footer,
footer {
  background: var(--glass-bg-primary) !important;
  backdrop-filter: blur(12px) saturate(180%) !important;
  -webkit-backdrop-filter: blur(12px) saturate(180%) !important;
  border-top: 1px solid var(--border-subtle) !important;
  color: var(--text-muted) !important;
  padding: 16px 20px;
}

/* ═══════════════════════════════════════════════════════════════
   SCROLLBAR
   ═══════════════════════════════════════════════════════════════ */

::-webkit-scrollbar {
  width: 12px;
  height: 12px;
}

::-webkit-scrollbar-track {
  background: rgba(15, 23, 42, 0.50);
  border-radius: 10px;
}

::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.35);
  border-radius: 10px;
  border: 2px solid rgba(15, 23, 42, 0.50);
}

::-webkit-scrollbar-thumb:hover {
  background: rgba(148, 163, 184, 0.55);
}

/* Firefox */
* {
  scrollbar-width: thin;
  scrollbar-color: rgba(148, 163, 184, 0.35) rgba(15, 23, 42, 0.50);
}

/* ═══════════════════════════════════════════════════════════════
   TYPOGRAPHY
   ═══════════════════════════════════════════════════════════════ */

h1, h2, h3, h4, h5, h6 {
  color: var(--text-white) !important;
  font-weight: 600;
  letter-spacing: -0.015em;
  margin-bottom: 16px;
}

p {
  color: var(--text-secondary) !important;
  margin-bottom: 12px;
  line-height: 1.7;
}

a:not(.btn) {
  color: var(--accent-secondary) !important;
  text-decoration: none;
  transition: color var(--transition-base);
}

a:not(.btn):hover {
  color: var(--accent-primary) !important;
  text-decoration: underline;
}

/* ═══════════════════════════════════════════════════════════════
   ACCESSIBILITY
   ═══════════════════════════════════════════════════════════════ */

*:focus-visible {
  outline: 2px solid var(--accent-primary) !important;
  outline-offset: 2px;
  border-radius: 4px;
}

button:focus-visible,
a:focus-visible,
.btn:focus-visible {
  outline: 2px solid var(--accent-primary) !important;
  outline-offset: 2px;
}

/* ═══════════════════════════════════════════════════════════════
   MOBILE RESPONSIVE
   ═══════════════════════════════════════════════════════════════ */

@media (max-width: 768px) {
  .content-wrapper,
  #app > div,
  .card-body,
  .box-body {
    padding: 16px !important;
  }

  .btn,
  button {
    padding: 8px 14px !important;
    font-size: 13px;
  }

  .table thead th,
  #app table thead th {
    font-size: 11px;
    padding: 10px 12px;
  }

  .table tbody td,
  #app table tbody td {
    padding: 10px 12px;
  }

  .modal-header,
  .modal-body,
  .modal-footer {
    padding: 16px !important;
  }

  .sidebar {
    height: 100vh;
  }
}

/* ═══════════════════════════════════════════════════════════════
   UTILITIES
   ═══════════════════════════════════════════════════════════════ */

.text-center { text-align: center !important; }
.text-right { text-align: right !important; }
.mt-0 { margin-top: 0 !important; }
.mb-0 { margin-bottom: 0 !important; }

/* ═══════════════════════════════════════════════════════════════
   END OF THEME
   ═══════════════════════════════════════════════════════════════ */
CSSEOF

echo "✓ CSS created: public/themes/noobee-glass.css"

# ============================================
# STEP 3: CREATE JAVASCRIPT FOR CHART.JS
# ============================================
echo "[3/6] Creating Chart.js override script..."

cat > public/themes/noobee-glass.js << "JSEOF"
/**
 * NOOBEE GLASS ULTRA — JavaScript Enhancements
 * Chart.js theming + Dynamic element fixes
 */

(function() {
  "use strict";

  // Wait for DOM to be ready
  function init() {
    // ══════════════════════════════════════════════════
    // CHART.JS GLOBAL DEFAULTS
    // ══════════════════════════════════════════════════
    if (typeof Chart !== "undefined") {
      Chart.defaults.color = "#e2e8f0";
      Chart.defaults.borderColor = "rgba(148, 163, 184, 0.15)";
      Chart.defaults.backgroundColor = "rgba(30, 41, 59, 0.75)";
      
      // Legend
      if (Chart.defaults.plugins && Chart.defaults.plugins.legend) {
        Chart.defaults.plugins.legend.labels.color = "#f8fafc";
      }
      
      // Tooltip
      if (Chart.defaults.plugins && Chart.defaults.plugins.tooltip) {
        Chart.defaults.plugins.tooltip.backgroundColor = "rgba(30, 41, 59, 0.95)";
        Chart.defaults.plugins.tooltip.titleColor = "#ffffff";
        Chart.defaults.plugins.tooltip.bodyColor = "#e2e8f0";
        Chart.defaults.plugins.tooltip.borderColor = "rgba(148, 163, 184, 0.25)";
        Chart.defaults.plugins.tooltip.borderWidth = 1;
      }
      
      // Grid
      if (Chart.defaults.scale) {
        Chart.defaults.scale.grid = Chart.defaults.scale.grid || {};
        Chart.defaults.scale.grid.color = "rgba(148, 163, 184, 0.08)";
        Chart.defaults.scale.ticks = Chart.defaults.scale.ticks || {};
        Chart.defaults.scale.ticks.color = "#94a3b8";
      }
    }

    // ══════════════════════════════════════════════════
    // FORCE SVG NAVBAR ICONS WHITE
    // ══════════════════════════════════════════════════
    function fixSVGColors() {
      const selectors = [
        "#app nav svg",
        "#app header svg",
        "nav[class*=\"sticky\"] svg",
        "header[class*=\"sticky\"] svg"
      ];
      
      selectors.forEach(selector => {
        document.querySelectorAll(selector).forEach(svg => {
          svg.style.color = "#ffffff";
          svg.querySelectorAll("*").forEach(el => {
            el.style.fill = "currentColor";
            el.style.stroke = "currentColor";
          });
        });
      });
    }

    // ══════════════════════════════════════════════════
    // OVERRIDE INLINE STYLES
    // ══════════════════════════════════════════════════
    function fixInlineStyles() {
      const elements = document.querySelectorAll(
        "#app div[style*=\"background\"], " +
        "#app div[style*=\"backgroundColor\"]"
      );
      
      elements.forEach(el => {
        const style = el.getAttribute("style") || "";
        // Check for gray inline backgrounds
        if (
          style.match(/rgb\(2[0-9],\s*2[0-9],\s*2[0-9]\)/) ||
          style.match(/rgb\(3[0-9],\s*3[0-9],\s*3[0-9]\)/) ||
          style.match(/#1[a-f0-9]{5}/)
        ) {
          el.style.background = "rgba(30, 41, 59, 0.75)";
          el.style.backdropFilter = "blur(12px) saturate(180%)";
          el.style.WebkitBackdropFilter = "blur(12px) saturate(180%)";
        }
      });
    }

    // ══════════════════════════════════════════════════
    // RUN FIXES
    // ══════════════════════════════════════════════════
    fixSVGColors();
    fixInlineStyles();

    // ══════════════════════════════════════════════════
    // MUTATION OBSERVER FOR DYNAMIC CONTENT
    // ══════════════════════════════════════════════════
    const observer = new MutationObserver(() => {
      fixSVGColors();
      fixInlineStyles();
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class"]
    });
  }

  // ══════════════════════════════════════════════════
  // INITIALIZE
  // ══════════════════════════════════════════════════
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // Re-run after React/Vue hydration
  setTimeout(init, 500);
  setTimeout(init, 1500);
})();
JSEOF

echo "✓ JS created: public/themes/noobee-glass.js"

# ============================================
# STEP 4: INJECT INTO ADMIN LAYOUT
# ============================================
echo "[4/6] Injecting theme into admin layout..."

ADMIN_LAYOUT="resources/views/layouts/admin.blade.php"

if [ -f "$ADMIN_LAYOUT" ]; then
  # Remove old injections first
  sed -i "/noobee-glass/d" "$ADMIN_LAYOUT" 2>/dev/null || true
  sed -i "/noobee-admin/d" "$ADMIN_LAYOUT" 2>/dev/null || true
  
  # Inject CSS and JS before </head>
  if ! grep -q "noobee-glass.css" "$ADMIN_LAYOUT"; then
    sed -i "s|</head>|    <link rel=\"stylesheet\" href=\"{{ asset('\''themes/noobee-glass.css'\'') }}\">\n    <script src=\"{{ asset('\''themes/noobee-glass.js'\'') }}\" defer></script>\n</head>|" "$ADMIN_LAYOUT"
    echo "✓ Injected into admin.blade.php"
  else
    echo "✓ Admin layout already has theme"
  fi
else
  echo "⚠ Admin layout not found at expected location"
fi

# ============================================
# STEP 5: INJECT INTO USER WRAPPER
# ============================================
echo "[5/6] Injecting theme into user wrapper..."

WRAPPER="resources/views/templates/wrapper.blade.php"

if [ -f "$WRAPPER" ]; then
  # Remove old injections
  sed -i "/noobee-glass/d" "$WRAPPER" 2>/dev/null || true
  sed -i "/noobee-admin/d" "$WRAPPER" 2>/dev/null || true
  sed -i "/noobee-user/d" "$WRAPPER" 2>/dev/null || true
  
  # Inject before </head>
  if ! grep -q "noobee-glass.css" "$WRAPPER"; then
    sed -i "s|</head>|    <link rel=\"stylesheet\" href=\"{{ asset('\''themes/noobee-glass.css'\'') }}\">\n    <script src=\"{{ asset('\''themes/noobee-glass.js'\'') }}\" defer></script>\n</head>|" "$WRAPPER"
    echo "✓ Injected into wrapper.blade.php"
  else
    echo "✓ Wrapper already has theme"
  fi
else
  echo "⚠ Wrapper not found at expected location"
fi

# ============================================
# STEP 6: CLEAR ALL CACHES
# ============================================
echo "[6/6] Clearing caches..."

php artisan view:clear 2>/dev/null || true
php artisan config:clear 2>/dev/null || true
php artisan cache:clear 2>/dev/null || true
php artisan route:clear 2>/dev/null || true
php artisan optimize:clear 2>/dev/null || true

# Clear OPcache if available
php -r "if (function_exists('"'opcache_reset'"')) { opcache_reset(); echo '\''OPcache cleared\n'\''; }" 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✓ NOOBEE GLASS ULTRA THEME — DEPLOYMENT COMPLETE"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Theme Files:"
echo "  • public/themes/noobee-glass.css"
echo "  • public/themes/noobee-glass.js"
echo ""
echo "Modified Layouts:"
echo "  • resources/views/layouts/admin.blade.php"
echo "  • resources/views/templates/wrapper.blade.php"
echo ""
echo "Coverage:"
echo "  ✓ Admin Panel (All Pages)"
echo "  ✓ User Dashboard"
echo "  ✓ Server Pages (Console, Files, Network, etc.)"
echo "  ✓ Login/Auth Pages"
echo "  ✓ Charts (CPU, RAM, Network graphs)"
echo "  ✓ Mobile Responsive"
echo ""
echo "Features:"
echo "  ✓ Modern Glassmorphism UI"
echo "  ✓ Chart.js Dark Theme"
echo "  ✓ SVG Icon Color Fix"
echo "  ✓ Sidebar Independent Scroll"
echo "  ✓ Production-Safe Overrides"
echo ""
echo "⚠️  IMPORTANT:"
echo "  1. Hard refresh: Ctrl+Shift+R (or Cmd+Shift+R)"
echo "  2. Clear browser cache completely"
echo "  3. If needed, restart PHP-FPM:"
echo "     systemctl restart php8.1-fpm"
echo ""
echo "════════════════════════════════════════════════════════════"
echo "ROLLBACK INSTRUCTIONS"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "To rollback this theme completely, run:"
echo ""
echo "bash -c '"'"'
cd /var/www/pterodactyl
rm -f public/themes/noobee-glass.{css,js}
[ -f storage/theme-backups/admin.blade.php.'"$TIMESTAMP"' ] && \\
  cp storage/theme-backups/admin.blade.php.'"$TIMESTAMP"' resources/views/layouts/admin.blade.php
[ -f storage/theme-backups/wrapper.blade.php.'"$TIMESTAMP"' ] && \\
  cp storage/theme-backups/wrapper.blade.php.'"$TIMESTAMP"' resources/views/templates/wrapper.blade.php
php artisan view:clear && php artisan optimize:clear
echo "✓ Theme rollback complete"
'"'"'
echo ""
echo "════════════════════════════════════════════════════════════"
echo ""
'