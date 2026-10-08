import initSqlJs from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DB_PATH = path.join(__dirname, 'aegisauth.db');
export const VAULT_STORAGE_PATH = path.join(__dirname, 'vault_storage');

if (!fs.existsSync(VAULT_STORAGE_PATH)) {
  fs.mkdirSync(VAULT_STORAGE_PATH, { recursive: true });
}

let sqlInstance = null;
let sqlDb = null;

function saveDatabase() {
  if (sqlDb) {
    try {
      const binaryArray = sqlDb.export();
      fs.writeFileSync(DB_PATH, Buffer.from(binaryArray));
    } catch (err) {
      console.error('Error saving SQLite database to disk:', err);
    }
  }
}

export const db = {
  prepare(query) {
    return {
      get(...params) {
        if (!sqlDb) throw new Error('Database not initialized');
        // Flatten params if passed as array
        const flatParams = params.length === 1 && Array.isArray(params[0]) ? params[0] : params;
        const stmt = sqlDb.prepare(query);
        stmt.bind(flatParams);
        if (stmt.step()) {
          const row = stmt.getAsObject();
          stmt.free();
          return row;
        }
        stmt.free();
        return null;
      },
      all(...params) {
        if (!sqlDb) throw new Error('Database not initialized');
        const flatParams = params.length === 1 && Array.isArray(params[0]) ? params[0] : params;
        const stmt = sqlDb.prepare(query);
        stmt.bind(flatParams);
        const rows = [];
        while (stmt.step()) {
          rows.push(stmt.getAsObject());
        }
        stmt.free();
        return rows;
      },
      run(...params) {
        if (!sqlDb) throw new Error('Database not initialized');
        const flatParams = params.length === 1 && Array.isArray(params[0]) ? params[0] : params;
        sqlDb.run(query, flatParams);
        saveDatabase();
        return { changes: 1 };
      }
    };
  },
  exec(sql) {
    if (!sqlDb) throw new Error('Database not initialized');
    sqlDb.exec(sql);
    saveDatabase();
  }
};

export async function initDatabase() {
  if (sqlDb) return db;

  sqlInstance = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    try {
      const fileBuffer = fs.readFileSync(DB_PATH);
      sqlDb = new sqlInstance.Database(fileBuffer);
    } catch (e) {
      console.warn('Could not read existing database file, creating fresh DB:', e.message);
      sqlDb = new sqlInstance.Database();
    }
  } else {
    sqlDb = new sqlInstance.Database();
  }

  // Create tables with parameterized security and indexes
  sqlDb.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      kba_question TEXT,
      kba_answer_hash TEXT,
      face_descriptor TEXT,
      mfa_secret TEXT,
      mfa_enabled INTEGER DEFAULT 1,
      risk_score INTEGER DEFAULT 15,
      failed_login_count INTEGER DEFAULT 0,
      locked_until TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS passkeys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      counter INTEGER DEFAULT 0,
      device_type TEXT DEFAULT 'singleDevice',
      backed_up INTEGER DEFAULT 0,
      transports TEXT,
      nickname TEXT DEFAULT 'Biometric / Windows Hello Key',
      created_at TEXT NOT NULL,
      last_used_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      mime_type TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      encryption_algorithm TEXT DEFAULT 'AES-256-GCM',
      tags TEXT,
      uploaded_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token TEXT NOT NULL,
      device_info TEXT,
      ip_address TEXT,
      location TEXT,
      risk_level TEXT DEFAULT 'LOW',
      auth_method TEXT NOT NULL,
      is_active INTEGER DEFAULT 1,
      created_at TEXT NOT NULL,
      last_active_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      user_email TEXT,
      event_type TEXT NOT NULL,
      risk_level TEXT DEFAULT 'LOW',
      status TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_alerts (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      ip_address TEXT,
      resolved INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      challenge TEXT NOT NULL,
      type TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS otp_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code TEXT NOT NULL,
      attempts INTEGER DEFAULT 0,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0
    );
  `);

  saveDatabase();
  await seedInitialData();

  return db;
}

async function seedInitialData() {
  const existingAdmin = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@aegisauth.io');
  
  if (!existingAdmin) {
    const adminId = 'usr_admin_' + Math.random().toString(36).substring(2, 9);
    const adminPassHash = await bcrypt.hash('AegisAdmin#2026!', 10);
    const adminKbaHash = await bcrypt.hash('olympus', 10);

    const userId = 'usr_alex_' + Math.random().toString(36).substring(2, 9);
    const userPassHash = await bcrypt.hash('SecurePass@2026!', 10);
    const userKbaHash = await bcrypt.hash('bunker7', 10);

    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO users (id, email, name, password_hash, role, kba_question, kba_answer_hash, mfa_secret, risk_score, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      adminId,
      'admin@aegisauth.io',
      'Aegis SecOps Officer',
      adminPassHash,
      'admin',
      'What was the codename of your primary air-gapped cryptographic facility?',
      adminKbaHash,
      'AEGIS_ADMIN_SECRET',
      12,
      now,
      now
    );

    db.prepare(`
      INSERT INTO users (id, email, name, password_hash, role, kba_question, kba_answer_hash, mfa_secret, risk_score, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      userId,
      'alex.chen@aegisauth.io',
      'Alex Chen',
      userPassHash,
      'user',
      'What is the serial code of your first hardware token?',
      userKbaHash,
      'AEGIS_USER_SECRET',
      18,
      now,
      now
    );

    // Initial audit events
    db.prepare(`
      INSERT INTO audit_logs (id, user_id, user_email, event_type, risk_level, status, details, ip_address, user_agent, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'aud_' + Math.random().toString(36).substring(2, 9),
      adminId,
      'admin@aegisauth.io',
      'SYSTEM_INITIALIZATION',
      'LOW',
      'SUCCESS',
      JSON.stringify({ note: 'AegisAuth Secure Core engine initialized with AES-256-GCM vault.' }),
      '127.0.0.1',
      'AegisCore/2.0 Kernel',
      now
    );

    // Initial security alert
    db.prepare(`
      INSERT INTO security_alerts (id, user_id, severity, title, description, ip_address, resolved, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'alt_' + Math.random().toString(36).substring(2, 9),
      adminId,
      'INFO',
      'Cryptographic Vault Initialized',
      'Hardware-isolated AES-256-GCM keys ready for zero-knowledge DigiLocker vault operations.',
      '127.0.0.1',
      0,
      now
    );

    // Seed sample documents in vault
    import('./utils/crypto.js').then(({ encryptBuffer }) => {
      const sampleDoc1 = Buffer.from(`CONFIDENTIAL AEGIS DIGITAL IDENTITY PASSPORT
ID: AG-8849-US
Holder: Alex Chen
Security Clearance: Level 4 Cryptographic Operator
Status: Active & Hardware-Signed
Issued: 2026-01-15 | Expires: 2036-01-15
Biometrics: FIDO2 WebAuthn & 128-Point Facial Vector Verified`);

      const enc1 = encryptBuffer(sampleDoc1);
      const file1Id = 'doc_' + Math.random().toString(36).substring(2, 9);
      const file1Path = path.join(VAULT_STORAGE_PATH, `${file1Id}.enc`);
      fs.writeFileSync(file1Path, enc1.encryptedBuffer);

      db.prepare(`
        INSERT INTO documents (id, user_id, title, category, file_name, file_path, file_size, mime_type, iv, auth_tag, tags, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        file1Id,
        userId,
        'National Digital Identity Card',
        'Identity',
        'National_ID_AlexChen.pdf',
        `${file1Id}.enc`,
        sampleDoc1.length,
        'application/pdf',
        enc1.ivHex,
        enc1.authTagHex,
        'identity,passport,verified,fido2',
        now
      );

      const sampleDoc2 = Buffer.from(`OFFSHORE MULTI-CLOUD RECOVERY KEYS
Cluster ID: SEC-CLUSTER-OMEGA
Algorithm: Ed25519 / RSA-4096 Hybrid
KMS Provider: Hardware Security Module (HSM) Level 3
Access Policy: Strict Dual-Custodian WebAuthn Approval Required`);

      const enc2 = encryptBuffer(sampleDoc2);
      const file2Id = 'doc_' + Math.random().toString(36).substring(2, 9);
      const file2Path = path.join(VAULT_STORAGE_PATH, `${file2Id}.enc`);
      fs.writeFileSync(file2Path, enc2.encryptedBuffer);

      db.prepare(`
        INSERT INTO documents (id, user_id, title, category, file_name, file_path, file_size, mime_type, iv, auth_tag, tags, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        file2Id,
        userId,
        'Cloud Recovery Disaster Certificates',
        'Confidential',
        'HSM_Recovery_Keys.txt',
        `${file2Id}.enc`,
        sampleDoc2.length,
        'text/plain',
        enc2.ivHex,
        enc2.authTagHex,
        'recovery,keys,backup,cloud',
        now
      );
    });
  }
}
