#!/bin/bash

###############################################################################
# CINELS GAME SERVER PANEL - ONE CLICK INSTALLER
# Domain: cinels.cibehost.site
# Author: AI Assistant
# Version: 1.0.0
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="cinels.cibehost.site"
PANEL_DIR="/opt/cinels-panel"
PANEL_PORT="3000"
ADMIN_EMAIL="admin@${DOMAIN}"

# Functions
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
    print_success "Root access confirmed"
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        
        if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
            print_error "This installer only supports Ubuntu/Debian"
            exit 1
        fi
        print_success "OS: $OS $VER"
    else
        print_error "Cannot determine OS"
        exit 1
    fi
}

update_system() {
    print_info "Updating system packages..."
    apt-get update -qq
    apt-get upgrade -y -qq
    print_success "System updated"
}

install_nodejs() {
    print_info "Installing Node.js 20.x LTS..."
    
    # Remove old nodejs if exists
    apt-get remove -y nodejs npm 2>/dev/null || true
    
    # Install NodeSource repository
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    # Verify installation
    NODE_VERSION=$(node -v)
    NPM_VERSION=$(npm -v)
    print_success "Node.js $NODE_VERSION installed"
    print_success "npm $NPM_VERSION installed"
}

install_nginx() {
    print_info "Installing Nginx..."
    apt-get install -y nginx
    systemctl enable nginx
    systemctl start nginx
    print_success "Nginx installed and started"
}

install_certbot() {
    print_info "Installing Certbot for SSL..."
    apt-get install -y certbot python3-certbot-nginx
    print_success "Certbot installed"
}

install_pm2() {
    print_info "Installing PM2 process manager..."
    npm install -g pm2
    pm2 startup systemd -u root --hp /root
    print_success "PM2 installed"
}

install_dependencies() {
    print_info "Installing system dependencies..."
    apt-get install -y \
        git \
        curl \
        wget \
        unzip \
        software-properties-common \
        build-essential \
        ufw \
        net-tools \
        htop
    print_success "Dependencies installed"
}

create_panel_directory() {
    print_info "Creating panel directory..."
    mkdir -p $PANEL_DIR
    cd $PANEL_DIR
    print_success "Directory created: $PANEL_DIR"
}

create_panel_structure() {
    print_info "Creating panel file structure..."
    
    # Create directories
    mkdir -p {src,public,logs,data,uploads,servers}
    mkdir -p src/{routes,controllers,models,middleware,utils}
    mkdir -p public/{css,js,assets}
    
    print_success "Panel structure created"
}

create_package_json() {
    print_info "Creating package.json..."
    
    cat > package.json << 'EOF'
{
  "name": "cinels-panel",
  "version": "1.0.0",
  "description": "Simple Game Server Control Panel",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js",
    "pm2:start": "pm2 start ecosystem.config.js",
    "pm2:stop": "pm2 stop cinels-panel",
    "pm2:restart": "pm2 restart cinels-panel",
    "pm2:logs": "pm2 logs cinels-panel"
  },
  "keywords": ["gameserver", "panel", "samp"],
  "author": "CINELS",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "express-async-handler": "^1.2.0",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "better-sqlite3": "^9.2.2",
    "ws": "^8.16.0",
    "multer": "^1.4.5-lts.1",
    "archiver": "^6.0.1",
    "node-schedule": "^2.1.1",
    "systeminformation": "^5.21.20",
    "node-pty": "^1.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  }
}
EOF
    
    print_success "package.json created"
}

create_env_file() {
    print_info "Creating .env configuration..."
    
    # Generate random JWT secret
    JWT_SECRET=$(openssl rand -base64 32)
    
    cat > .env << EOF
NODE_ENV=production
PORT=$PANEL_PORT
DOMAIN=$DOMAIN

# Security
JWT_SECRET=$JWT_SECRET
SESSION_TIMEOUT=86400000

# Paths
PANEL_DIR=$PANEL_DIR
SERVERS_DIR=$PANEL_DIR/servers
UPLOADS_DIR=$PANEL_DIR/uploads
DATA_DIR=$PANEL_DIR/data

# Database
DB_PATH=$PANEL_DIR/data/panel.db

# Default Admin
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123
ADMIN_EMAIL=$ADMIN_EMAIL

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
EOF
    
    chmod 600 .env
    print_success ".env file created"
    print_warning "Default admin password: changeme123 - CHANGE THIS!"
}

create_pm2_config() {
    print_info "Creating PM2 ecosystem config..."
    
    cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'cinels-panel',
    script: './src/server.js',
    instances: 2,
    exec_mode: 'cluster',
    autorestart: true,
    watch: false,
    max_memory_restart: '500M',
    env: {
      NODE_ENV: 'production'
    },
    error_file: './logs/error.log',
    out_file: './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true
  }]
};
EOF
    
    print_success "PM2 config created"
}

create_backend_files() {
    print_info "Creating backend application files..."
    
    # Main server file
    cat > src/server.js << 'EOF'
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const Database = require('./models/database');
const WebSocketServer = require('./utils/websocket');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Database
Database.init();

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: false // Will configure properly later
}));

// Compression
app.use(compression());

// CORS
app.use(cors());

// Rate Limiting
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Body Parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static Files
app.use(express.static(path.join(__dirname, '../public')));

// API Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/servers', require('./routes/servers'));
app.use('/api/files', require('./routes/files'));
app.use('/api/system', require('./routes/system'));

// Root Route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Error Handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error'
    });
});

// Start Server
const server = app.listen(PORT, () => {
    console.log(`✓ Panel running on port ${PORT}`);
    console.log(`✓ Environment: ${process.env.NODE_ENV}`);
    console.log(`✓ Domain: ${process.env.DOMAIN}`);
});

// Initialize WebSocket
const wss = new WebSocketServer(server);

// Graceful Shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

module.exports = app;
EOF

    # Database Model
    cat > src/models/database.js << 'EOF'
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../data/panel.db');

let db;

function init() {
    // Ensure data directory exists
    const dataDir = path.dirname(DB_PATH);
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }

    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    
    createTables();
    createDefaultAdmin();
    
    console.log('✓ Database initialized');
}

function createTables() {
    // Users table
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Servers table
    db.exec(`
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            game_type TEXT NOT NULL,
            port INTEGER NOT NULL,
            max_players INTEGER DEFAULT 50,
            status TEXT DEFAULT 'stopped',
            user_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Logs table
    db.exec(`
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
    `);
}

function createDefaultAdmin() {
    const admin = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
    
    if (!admin) {
        const hashedPassword = bcrypt.hashSync('changeme123', 10);
        db.prepare(`
            INSERT INTO users (username, password, email, role) 
            VALUES (?, ?, ?, ?)
        `).run('admin', hashedPassword, 'admin@cinels.local', 'admin');
        
        console.log('✓ Default admin user created (admin/changeme123)');
    }
}

function getDB() {
    return db;
}

module.exports = {
    init,
    getDB
};
EOF

    # WebSocket Server
    cat > src/utils/websocket.js << 'EOF'
const WebSocket = require('ws');

class WebSocketServer {
    constructor(server) {
        this.wss = new WebSocket.Server({ server, path: '/ws' });
        this.clients = new Map();
        
        this.wss.on('connection', this.handleConnection.bind(this));
        console.log('✓ WebSocket server initialized');
    }

    handleConnection(ws, req) {
        const clientId = Date.now();
        this.clients.set(clientId, ws);
        
        console.log(`Client ${clientId} connected`);

        ws.on('message', (message) => {
            try {
                const data = JSON.parse(message);
                this.handleMessage(clientId, data);
            } catch (err) {
                console.error('Invalid message:', err);
            }
        });

        ws.on('close', () => {
            this.clients.delete(clientId);
            console.log(`Client ${clientId} disconnected`);
        });

        ws.send(JSON.stringify({ 
            type: 'connected', 
            message: 'Connected to panel' 
        }));
    }

    handleMessage(clientId, data) {
        // Handle different message types
        console.log(`Message from ${clientId}:`, data);
    }

    broadcast(data) {
        const message = JSON.stringify(data);
        this.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    }

    sendToClient(clientId, data) {
        const client = this.clients.get(clientId);
        if (client && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    }
}

module.exports = WebSocketServer;
EOF

    print_success "Backend files created"
}

create_routes() {
    print_info "Creating API routes..."
    
    # Auth routes
    cat > src/routes/auth.js << 'EOF'
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('../models/database');

router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const db = Database.getDB();
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            user: { 
                id: user.id, 
                username: user.username, 
                email: user.email,
                role: user.role 
            } 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/change-password', async (req, res) => {
    // TODO: Implement password change
    res.json({ message: 'Not implemented yet' });
});

module.exports = router;
EOF

    # Servers routes
    cat > src/routes/servers.js << 'EOF'
const express = require('express');
const router = express.Router();
const Database = require('../models/database');

router.get('/', (req, res) => {
    const db = Database.getDB();
    const servers = db.prepare('SELECT * FROM servers').all();
    res.json(servers);
});

router.post('/', (req, res) => {
    // TODO: Create server
    res.json({ message: 'Create server - Not implemented' });
});

router.delete('/:id', (req, res) => {
    // TODO: Delete server
    res.json({ message: 'Delete server - Not implemented' });
});

module.exports = router;
EOF

    # Files routes
    cat > src/routes/files.js << 'EOF'
const express = require('express');
const router = express.Router();

router.get('/:serverId', (req, res) => {
    // TODO: List files
    res.json({ message: 'List files - Not implemented' });
});

module.exports = router;
EOF

    # System routes
    cat > src/routes/system.js << 'EOF'
const express = require('express');
const router = express.Router();
const si = require('systeminformation');

router.get('/stats', async (req, res) => {
    try {
        const cpu = await si.currentLoad();
        const mem = await si.mem();
        const disk = await si.fsSize();
        
        res.json({
            cpu: cpu.currentLoad.toFixed(2),
            memory: {
                total: (mem.total / 1024 / 1024 / 1024).toFixed(2),
                used: (mem.used / 1024 / 1024 / 1024).toFixed(2),
                percentage: ((mem.used / mem.total) * 100).toFixed(2)
            },
            disk: disk[0] ? {
                total: (disk[0].size / 1024 / 1024 / 1024).toFixed(2),
                used: (disk[0].used / 1024 / 1024 / 1024).toFixed(2),
                percentage: disk[0].use.toFixed(2)
            } : null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
EOF

    print_success "API routes created"
}

create_frontend() {
    print_info "Creating frontend files..."
    
    # HTML
    cat > public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CINELS Panel - Game Server Management</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', system-ui, sans-serif; }
    </style>
</head>
<body class="bg-gray-900 text-gray-100">
    <div id="app" class="min-h-screen">
        <!-- Login Screen -->
        <div id="loginScreen" class="flex items-center justify-center min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
            <div class="bg-gray-800 p-8 rounded-lg shadow-2xl w-full max-w-md">
                <div class="text-center mb-8">
                    <h1 class="text-3xl font-bold text-purple-400">CINELS PANEL</h1>
                    <p class="text-gray-400 mt-2">Game Server Management</p>
                </div>
                <form id="loginForm">
                    <div class="mb-4">
                        <label class="block text-sm font-medium mb-2">Username</label>
                        <input type="text" id="username" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-purple-500" required>
                    </div>
                    <div class="mb-6">
                        <label class="block text-sm font-medium mb-2">Password</label>
                        <input type="password" id="password" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-purple-500" required>
                    </div>
                    <button type="submit" class="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 px-4 rounded-lg transition">
                        Login
                    </button>
                </form>
                <div id="loginError" class="mt-4 text-red-400 text-sm hidden"></div>
            </div>
        </div>

        <!-- Dashboard -->
        <div id="dashboard" class="hidden">
            <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
                <div class="flex justify-between items-center">
                    <h1 class="text-2xl font-bold text-purple-400">CINELS PANEL</h1>
                    <div class="flex items-center gap-4">
                        <span id="userDisplay" class="text-gray-400"></span>
                        <button onclick="logout()" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg transition">
                            <i class="fas fa-sign-out-alt mr-2"></i>Logout
                        </button>
                    </div>
                </div>
            </nav>

            <div class="p-6">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                    <div class="bg-gray-800 p-6 rounded-lg">
                        <h3 class="text-gray-400 text-sm mb-2">CPU Usage</h3>
                        <p id="cpuStat" class="text-3xl font-bold text-purple-400">0%</p>
                    </div>
                    <div class="bg-gray-800 p-6 rounded-lg">
                        <h3 class="text-gray-400 text-sm mb-2">Memory</h3>
                        <p id="memStat" class="text-3xl font-bold text-blue-400">0 GB</p>
                    </div>
                    <div class="bg-gray-800 p-6 rounded-lg">
                        <h3 class="text-gray-400 text-sm mb-2">Servers</h3>
                        <p id="serverCount" class="text-3xl font-bold text-green-400">0</p>
                    </div>
                </div>

                <div class="bg-gray-800 p-6 rounded-lg">
                    <h2 class="text-xl font-bold mb-4">Your Servers</h2>
                    <div id="serversList" class="text-gray-400">
                        No servers yet. Panel is ready!
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="/js/app.js"></script>
</body>
</html>
EOF

    # JavaScript
    cat > public/js/app.js << 'EOF'
let token = localStorage.getItem('token');
let ws = null;

// Check auth on load
if (token) {
    showDashboard();
} else {
    showLogin();
}

// Login form
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();
        
        if (res.ok) {
            token = data.token;
            localStorage.setItem('token', token);
            localStorage.setItem('user', JSON.stringify(data.user));
            showDashboard();
        } else {
            showError(data.error || 'Login failed');
        }
    } catch (err) {
        showError('Connection error');
    }
});

function showLogin() {
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('dashboard').classList.add('hidden');
}

function showDashboard() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    
    const user = JSON.parse(localStorage.getItem('user'));
    document.getElementById('userDisplay').textContent = user.username;
    
    loadStats();
    loadServers();
    connectWebSocket();
    
    // Refresh stats every 5 seconds
    setInterval(loadStats, 5000);
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    if (ws) ws.close();
    showLogin();
}

function showError(msg) {
    const errorDiv = document.getElementById('loginError');
    errorDiv.textContent = msg;
    errorDiv.classList.remove('hidden');
    setTimeout(() => errorDiv.classList.add('hidden'), 3000);
}

async function loadStats() {
    try {
        const res = await fetch('/api/system/stats', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        
        document.getElementById('cpuStat').textContent = data.cpu + '%';
        document.getElementById('memStat').textContent = data.memory.used + ' GB';
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

async function loadServers() {
    try {
        const res = await fetch('/api/servers', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const servers = await res.json();
        
        document.getElementById('serverCount').textContent = servers.length;
        
        if (servers.length === 0) {
            document.getElementById('serversList').innerHTML = 'No servers yet. Panel is ready!';
        }
    } catch (err) {
        console.error('Failed to load servers:', err);
    }
}

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    
    ws.onopen = () => console.log('WebSocket connected');
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('WS message:', data);
    };
    ws.onerror = (err) => console.error('WebSocket error:', err);
    ws.onclose = () => {
        console.log('WebSocket disconnected');
        setTimeout(connectWebSocket, 5000);
    };
}
EOF

    print_success "Frontend files created"
}

install_panel_packages() {
    print_info "Installing Node.js packages..."
    cd $PANEL_DIR
    npm install --production
    print_success "Packages installed"
}

configure_nginx() {
    print_info "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/$DOMAIN << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    
    # SSL certificates will be added by Certbot
    
    location / {
        proxy_pass http://localhost:$PANEL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    location /ws {
        proxy_pass http://localhost:$PANEL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    nginx -t
    systemctl reload nginx
    
    print_success "Nginx configured"
}

setup_ssl() {
    print_info "Setting up SSL certificate..."
    print_warning "Make sure DNS for $DOMAIN points to this server!"
    
    read -p "Press Enter to continue with SSL setup or Ctrl+C to cancel..."
    
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $ADMIN_EMAIL --redirect
    
    if [ $? -eq 0 ]; then
        print_success "SSL certificate installed"
        
        # Setup auto-renewal
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'") | crontab -
        print_success "Auto-renewal configured"
    else
        print_error "SSL setup failed - you can run 'certbot --nginx -d $DOMAIN' manually later"
    fi
}

configure_firewall() {
    print_info "Configuring firewall..."
    
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 'Nginx Full'
    ufw allow 7777:7877/udp  # SAMP server ports
    
    print_success "Firewall configured"
}

start_panel() {
    print_info "Starting panel with PM2..."
    
    cd $PANEL_DIR
    pm2 start ecosystem.config.js
    pm2 save
    
    print_success "Panel started"
}

print_completion() {
    clear
    echo ""
    echo "=========================================="
    echo -e "${GREEN}  CINELS PANEL INSTALLATION COMPLETE!${NC}"
    echo "=========================================="
    echo ""
    echo -e "${BLUE}Panel URL:${NC} https://$DOMAIN"
    echo -e "${BLUE}Admin User:${NC} admin"
    echo -e "${YELLOW}Admin Pass:${NC} changeme123"
    echo ""
    echo -e "${YELLOW}⚠  IMPORTANT:${NC}"
    echo "1. Change admin password immediately!"
    echo "2. Panel is running in PM2 cluster mode"
    echo "3. Logs: pm2 logs cinels-panel"
    echo ""
    echo -e "${GREEN}Useful Commands:${NC}"
    echo "  pm2 status          - Check status"
    echo "  pm2 restart cinels-panel - Restart"
    echo "  pm2 logs cinels-panel    - View logs"
    echo "  pm2 monit           - Monitor resources"
    echo ""
    echo "=========================================="
    echo ""
}

# Main Installation Flow
main() {
    clear
    echo "=========================================="
    echo "  CINELS GAME SERVER PANEL INSTALLER"
    echo "  Domain: $DOMAIN"
    echo "=========================================="
    echo ""
    
    check_root
    check_os
    
    print_info "Starting installation..."
    sleep 2
    
    update_system
    install_dependencies
    install_nodejs
    install_nginx
    install_certbot
    install_pm2
    
    create_panel_directory
    create_panel_structure
    create_package_json
    create_env_file
    create_pm2_config
    create_backend_files
    create_routes
    create_frontend
    install_panel_packages
    
    configure_nginx
    configure_firewall
    
    start_panel
    
    setup_ssl
    
    print_completion
}

# Run installer
main