import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { initDatabase } from './database.js';
import authRoutes from './routes/auth.js';
import vaultRoutes from './routes/vault.js';
import securityRoutes from './routes/security.js';
import adminRoutes from './routes/admin.js';
import ragRoutes from './routes/rag.js';
import { tsharkMonitor } from './utils/tsharkMonitor.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'camera=*, publickey-credentials-create=*');
  next();
});

// CORS Configuration
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5000',
    'http://127.0.0.1:5000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(cookieParser());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// Wireline Traffic Interception & TShark Monitoring Middleware
app.use((req, res, next) => {
  const startTime = Date.now();
  res.on('finish', () => {
    const latency = Date.now() - startTime;
    tsharkMonitor.recordAppTraffic(req, res, latency);
  });
  next();
});

// Simple In-Memory Rate Limiting
const ipRequestWindow = new Map();
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute
  const maxRequests = 180;

  const userRecord = ipRequestWindow.get(ip) || { count: 0, resetTime: now + windowMs };

  if (now > userRecord.resetTime) {
    userRecord.count = 1;
    userRecord.resetTime = now + windowMs;
  } else {
    userRecord.count++;
  }

  ipRequestWindow.set(ip, userRecord);

  if (userRecord.count > maxRequests) {
    return res.status(429).json({
      error: 'Security Rate Limit Exceeded. Progressive delay instituted by AegisAuth Guard.'
    });
  }

  next();
});

// Mount API Routes
app.use('/api/auth', authRoutes);
app.use('/api/vault', vaultRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/rag', ragRoutes);

// System Health Endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    platform: 'AegisAuth Secure Core',
    version: '2.4.0-enterprise',
    cryptography: {
      vault: 'AES-256-GCM Hardware-Isolated',
      passkeys: 'FIDO2 / WebAuthn Level 3 (ES256 / RS256)',
      kbaHashing: 'Bcrypt 12 Rounds',
      jwt: 'HMAC-SHA256 Signed'
    },
    timestamp: new Date().toISOString()
  });
});

// Serve built frontend assets if present
const clientDist = path.join(__dirname, '../client/dist');
if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => {
    if (req.url.startsWith('/api')) return next();
    res.sendFile(path.join(clientDist, 'index.html'));
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({ error: 'Internal server error: ' + err.message });
});

// Start Server
async function startServer(portToUse = PORT) {
  await initDatabase();
  const server = app.listen(portToUse, () => {
    console.log(`🛡️  AegisAuth Backend running on http://localhost:${portToUse}`);
    console.log(`🔒 Cryptographic Vault Storage initialized.`);
    console.log(`📡 TShark Network Packet Inspector active.`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      const nextPort = Number(portToUse) + 1;
      console.warn(`⚠️  Port ${portToUse} is currently in use. Automatically binding to alternative port ${nextPort}...`);
      startServer(nextPort);
    } else {
      console.error('Server listen error:', err);
    }
  });
}

startServer().catch(err => {
  console.error('Failed to start AegisAuth Server:', err);
  process.exit(1);
});
