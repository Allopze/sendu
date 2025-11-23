import 'dotenv/config'; // Cargar variables de entorno
import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import cors from 'cors';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import session from 'express-session';
import bcrypt from 'bcrypt';
import connectSqlite3 from 'connect-sqlite3';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';

// --- Configuración Inicial ---
const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Rutas de almacenamiento y DB
const STORAGE_PATH = process.env.STORAGE_PATH || path.join(__dirname, '../uploads');
const BRANDING_PATH = path.join(STORAGE_PATH, 'branding');
const DB_PATH = path.join(__dirname, '../db.sqlite');
const FRONTEND_PATH = path.join(__dirname, '../frontend');
const CHUNKS_PATH = path.join(STORAGE_PATH, 'chunks');
const fsp = fs.promises;
const SQLiteStore = connectSqlite3(session);
const SESSION_DB_DIR = path.dirname(DB_PATH);
const SESSION_DB_NAME = process.env.SESSION_DB_NAME || 'sessions.sqlite';
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.PASSWORD_SECRET || 'default-secret-change-this';
const isProduction = process.env.NODE_ENV === 'production';
const sessionCookieSecure = process.env.SESSION_COOKIE_SECURE === 'true'; // Por defecto false para permitir HTTP/Cloudflare flexible
const allowedSameSite = new Set(['lax', 'strict', 'none']);
let cookieSameSite = (process.env.SESSION_COOKIE_SAMESITE || 'lax').toLowerCase();
if (!allowedSameSite.has(cookieSameSite)) {
  cookieSameSite = 'lax';
}
const sessionCookieOptions = {
  secure: sessionCookieSecure || cookieSameSite === 'none',
  httpOnly: true,
  sameSite: cookieSameSite,
  maxAge: 1000 * 60 * 60 * 24 * 7
};

// Asegurarse de que el directorio de subida exista
fs.mkdirSync(STORAGE_PATH, { recursive: true });
fs.mkdirSync(CHUNKS_PATH, { recursive: true });
fs.mkdirSync(BRANDING_PATH, { recursive: true });

// --- Base de Datos (SQLite) ---
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL'); // Habilitar modo WAL para mejor concurrencia y rendimiento

// Crear tablas si no existen
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    passwordHash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    createdAt INTEGER NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    originalName TEXT NOT NULL,
    serverPath TEXT NOT NULL,
    mimeType TEXT NOT NULL,
    size INTEGER NOT NULL,
    createdAt INTEGER NOT NULL,
    expiresAt INTEGER,
    maxDownloads INTEGER,
    downloadCount INTEGER DEFAULT 0,
    passwordHash TEXT,
    userId TEXT,
    FOREIGN KEY (userId) REFERENCES users(id)
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    fileId TEXT NOT NULL,
    reason TEXT NOT NULL,
    createdAt INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY (fileId) REFERENCES files(id)
  );
`);

// Inicializar configuración del footer por defecto si no existe
const defaultFooterConfig = {
  brandName: "Sendu",
  tagline: "Envía y comparte archivos de forma segura.",
  logoLight: "/assets/branding/sendu-light.svg",
  logoDark: "/assets/branding/sendu-dark.svg",
  contactLinks: [
    { text: "Email", url: "mailto:contacto@sendu.com" },
    { text: "Teléfono", url: "tel:+1234567890" },
    { text: "Soporte", url: "#" }
  ],
  moreLinks: [
    { text: "Sendu", url: "https://sendu.com" },
    { text: "Próximamente", url: "#" }
  ]
};

const existingFooterConfig = db.prepare('SELECT value FROM settings WHERE key = ?').get('footer_config');
if (!existingFooterConfig) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('footer_config', JSON.stringify(defaultFooterConfig));
}

// Garantizar columnas nuevas cuando se usa una base previa sin migraciones
const ensureColumn = (tableName, columnName, definition) => {
  const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
  const hasColumn = columns.some((column) => column.name === columnName);
  if (!hasColumn) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${definition}`);
  }
};

ensureColumn('files', 'userId', 'userId TEXT');
ensureColumn('users', 'role', "role TEXT DEFAULT 'user'");
ensureColumn('users', 'resetToken', 'resetToken TEXT');
ensureColumn('users', 'resetTokenExpires', 'resetTokenExpires INTEGER');

// --- Middlewares ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
    },
  },
}));

// Rate Limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // Límite de 10 intentos por IP
  message: { message: 'Demasiados intentos de inicio de sesión, por favor intente más tarde.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 100, // Límite de 100 subidas por IP por hora
  message: { message: 'Límite de subidas excedido, por favor espere.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/upload', uploadLimiter);

app.use(cors({
  origin: true,
  credentials: true
})); // Habilitar CORS con credenciales
app.use(express.json()); // Parsear JSON
app.use(express.urlencoded({ extended: true })); // Parsear form-data

// Configurar sesiones persistentes en SQLite
app.use(session({
  store: new SQLiteStore({
    db: SESSION_DB_NAME,
    dir: SESSION_DB_DIR,
    concurrentDB: false,
    cleanupInterval: 24 * 60 * 60 * 1000 // limpiar sesiones expiradas una vez al día
  }),
  name: process.env.SESSION_COOKIE_NAME || 'sendu.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: sessionCookieOptions
}));

// ¡Crítico para proxies inversos! (Nginx, Caddy, Cloudflare)
// Confía en el header X-Forwarded-For para obtener la IP real del cliente.
app.set('trust proxy', true);

// Middleware de detección LAN/WAN
const stripTrailingSlash = (value) => {
  if (!value) return value;
  return value.replace(/\/+$/, '');
};

const detectOrigin = (req, res, next) => {
  const clientIp = req.ip; // req.ip usará X-Forwarded-For gracias a 'trust proxy'
  const clientHost = req.get('host') || req.hostname || '';
  const forwardedProtoHeader = req.headers['x-forwarded-proto'];
  const forwardedProto = Array.isArray(forwardedProtoHeader)
    ? forwardedProtoHeader[0]
    : (forwardedProtoHeader || '');
  const protocol = forwardedProto.split(',')[0].trim() || req.protocol;

  const defaultOrigin = clientHost ? `${protocol}://${clientHost}` : '';
  const localOrigin = stripTrailingSlash(process.env.LOCAL_ORIGIN) || stripTrailingSlash(defaultOrigin);
  const publicOrigin = stripTrailingSlash(process.env.PUBLIC_ORIGIN) || stripTrailingSlash(defaultOrigin);

  // Expresión regular para IPs privadas (incluye loopback)
  const isPrivateIp = /^(127\.)|(10\.)|(172\.(1[6-9]|2[0-9]|3[0-1])\.)|(192\.168\.)/.test(clientIp || '');
  // Comprobar si el host termina en .local o .lan
  const isLocalHost = clientHost.endsWith('.local') || clientHost.endsWith('.lan');

  if (isPrivateIp || isLocalHost) {
    req.originType = 'local';
    req.downloadOrigin = localOrigin;
  } else {
    req.originType = 'public';
    req.downloadOrigin = publicOrigin;
  }

  if (!req.downloadOrigin) {
    req.downloadOrigin = stripTrailingSlash(defaultOrigin);
  }

  next();
};

// --- Funciones de Utilidad ---

// Middleware de autenticación
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'No autorizado. Inicia sesión.' });
  }
  next();
};

// Middleware de autorización de administrador
const requireAdmin = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'No autorizado. Inicia sesión.' });
  }
  if (req.session.userRole !== 'admin') {
    return res.status(403).json({ message: 'Acceso denegado. Se requieren permisos de administrador.' });
  }
  next();
};

// Hashear contraseña para archivos (mantener compatibilidad)
const hashPassword = (password) => {
  if (!password) return null;
  const secret = process.env.PASSWORD_SECRET || 'default-secret';
  return crypto.createHmac('sha256', secret).update(password).digest('hex');
};

// --- Configuración de Almacenamiento (Multer) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, STORAGE_PATH);
  },
  filename: (req, file, cb) => {
    // Usar UUID para el nombre de archivo en el servidor para evitar colisiones
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE || 10737418240) } // 10GB por defecto
}).single('file'); // 'file' debe coincidir con el nombre del campo en FormData

// Configuración de Multer para Branding
const brandingStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, BRANDING_PATH);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9]/g, '-');
    cb(null, `${name}-${Date.now()}${ext}`);
  }
});
const uploadBranding = multer({ 
    storage: brandingStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Solo se permiten imágenes.'));
        }
    }
}).single('file');

// --- RUTAS DE API ---

// --- AUTH ENDPOINTS ---

// POST /api/auth/register - Registrar nuevo usuario
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Todos los campos son requeridos.' });
    }

    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'El email no es válido.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres.' });
    }

    // Verificar si el usuario ya existe
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
    if (existingUser) {
      return res.status(409).json({ message: 'El email o usuario ya está registrado.' });
    }

    // Hashear contraseña con bcrypt
    const passwordHash = await bcrypt.hash(password, 10);

    // Crear usuario
    const userId = uuidv4();
    const role = 'user'; // Por defecto todos son usuarios normales
    const stmt = db.prepare('INSERT INTO users (id, email, username, passwordHash, role, createdAt) VALUES (?, ?, ?, ?, ?, ?)');
    stmt.run(userId, email, username, passwordHash, role, Date.now());

    // Crear sesión
    req.session.userId = userId;
    req.session.username = username;
    req.session.userRole = role;

    res.status(201).json({
      message: 'Usuario registrado con éxito.',
      user: { id: userId, email, username, role }
    });

  } catch (err) {
    console.error('Error en registro:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/auth/login - Iniciar sesión
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({ message: 'Todos los campos son requeridos.' });
    }

    // Buscar usuario por email o username
    const user = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(emailOrUsername, emailOrUsername);

    if (!user) {
      return res.status(401).json({ message: 'Credenciales incorrectas.' });
    }

    // Verificar contraseña
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ message: 'Credenciales incorrectas.' });
    }

    // Crear sesión
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.userRole = user.role || 'user';

    res.json({
      message: 'Inicio de sesión exitoso.',
      user: { id: user.id, email: user.email, username: user.username, role: user.role || 'user' }
    });

  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/auth/logout - Cerrar sesión
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Error al cerrar sesión.' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Sesión cerrada.' });
  });
});

// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.example.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER || 'user',
    pass: process.env.SMTP_PASS || 'pass'
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email requerido.' });

    const user = db.prepare('SELECT id, username FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.json({ message: 'Si el email existe, se enviará un enlace de recuperación.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000; // 1 hora

    db.prepare('UPDATE users SET resetToken = ?, resetTokenExpires = ? WHERE id = ?')
      .run(token, expires, user.id);

    const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${token}`;

    if (!process.env.SMTP_HOST) {
      console.log(`[DEV] Reset Link para ${email}: ${resetLink}`);
      return res.json({ message: 'Si el email existe, se enviará un enlace de recuperación. (Revisa la consola del servidor en modo DEV)' });
    }

    await transporter.sendMail({
      from: process.env.SMTP_FROM || '"Sendu" <noreply@sendu.local>',
      to: email,
      subject: 'Recuperación de contraseña - Sendu',
      html: `<p>Hola ${user.username},</p>
             <p>Has solicitado restablecer tu contraseña.</p>
             <p>Haz clic en el siguiente enlace para continuar:</p>
             <a href="${resetLink}">${resetLink}</a>
             <p>Este enlace expira en 1 hora.</p>`
    });

    res.json({ message: 'Si el email existe, se enviará un enlace de recuperación.' });

  } catch (err) {
    console.error('Error en forgot-password:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ message: 'Token y nueva contraseña requeridos.' });

    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres.' });
    }

    const user = db.prepare('SELECT id FROM users WHERE resetToken = ? AND resetTokenExpires > ?').get(token, Date.now());

    if (!user) {
      return res.status(400).json({ message: 'Token inválido o expirado.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    db.prepare('UPDATE users SET passwordHash = ?, resetToken = NULL, resetTokenExpires = NULL WHERE id = ?')
      .run(passwordHash, user.id);

    res.json({ message: 'Contraseña restablecida con éxito. Ahora puedes iniciar sesión.' });

  } catch (err) {
    console.error('Error en reset-password:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/auth/me - Obtener usuario actual
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'No autenticado.' });
  }

  const user = db.prepare('SELECT id, email, username, role, createdAt FROM users WHERE id = ?').get(req.session.userId);
  
  if (!user) {
    return res.status(404).json({ message: 'Usuario no encontrado.' });
  }

  // Calcular uso de almacenamiento
  const storageUsed = db.prepare('SELECT SUM(size) as total FROM files WHERE userId = ?').get(user.id).total || 0;
  user.storageUsed = storageUsed;
  user.storageLimit = 100 * 1024 * 1024 * 1024; // 100GB

  res.json({ user });
});

// GET /health - Healthcheck para Cloudflare/Docker
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: Date.now() });
});

// --- ADMIN ENDPOINTS ---

// GET /api/admin/stats - Obtener estadísticas del sistema (solo admin)
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const totalFiles = db.prepare('SELECT COUNT(*) as count FROM files').get().count;
    const totalDownloads = db.prepare('SELECT SUM(downloadCount) as total FROM files').get().total || 0;
    const users = db.prepare('SELECT id, email, username, role, createdAt FROM users ORDER BY createdAt DESC').all();
    const recentFiles = db.prepare(`
      SELECT f.id, f.originalName, f.size, f.createdAt, f.downloadCount, u.username
      FROM files f
      LEFT JOIN users u ON f.userId = u.id
      ORDER BY f.createdAt DESC
      LIMIT 10
    `).all();

    res.json({
      stats: {
        totalUsers,
        totalFiles,
        totalDownloads
      },
      users,
      recentFiles
    });
  } catch (err) {
    console.error('Error obteniendo estadísticas:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/admin/users - Obtener lista de usuarios con detalles
app.get('/api/admin/users', requireAdmin, (req, res) => {
  try {
    const users = db.prepare(`
      SELECT 
        u.id, u.email, u.username, u.role, u.createdAt,
        COUNT(f.id) as fileCount,
        COALESCE(SUM(f.size), 0) as totalSize,
        COALESCE(SUM(f.downloadCount), 0) as totalDownloads
      FROM users u
      LEFT JOIN files f ON u.id = f.userId
      GROUP BY u.id
      ORDER BY u.createdAt DESC
    `).all();

    res.json({ users });
  } catch (err) {
    console.error('Error obteniendo usuarios:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// PATCH /api/admin/users/:id/role - Cambiar rol de usuario
app.patch('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  try {
    const { role } = req.body;
    const userId = req.params.id;

    if (!role || !['user', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Rol inválido. Debe ser "user" o "admin".' });
    }

    // No permitir que un admin se quite a sí mismo el rol admin si es el único
    if (userId === req.session.userId && role === 'user') {
      const adminCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get('admin').count;
      if (adminCount <= 1) {
        return res.status(400).json({ message: 'No puedes quitarte el rol de admin si eres el único administrador.' });
      }
    }

    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, userId);

    res.json({ message: `Rol de ${user.username} actualizado a ${role}.` });
  } catch (err) {
    console.error('Error cambiando rol:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// PUT /api/admin/users/:id - Actualizar usuario completo (admin)
app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  try {
    const userId = req.params.id;
    const { email, username, role } = req.body;

    if (!email && !username && !role) {
      return res.status(400).json({ message: 'No hay datos para actualizar.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    const updates = [];
    const params = [];

    if (email && email !== user.email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Email inválido.' });
        }
        const existing = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(email, userId);
        if (existing) return res.status(409).json({ message: 'Email ya en uso.' });
        
        updates.push('email = ?');
        params.push(email);
    }

    if (username && username !== user.username) {
        if (username.length < 3) return res.status(400).json({ message: 'Usuario muy corto.' });
        const existing = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(username, userId);
        if (existing) return res.status(409).json({ message: 'Usuario ya en uso.' });

        updates.push('username = ?');
        params.push(username);
    }

    if (role && role !== user.role) {
        if (!['user', 'admin'].includes(role)) return res.status(400).json({ message: 'Rol inválido.' });
        
        if (userId === req.session.userId && role === 'user') {
             const adminCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get('admin').count;
             if (adminCount <= 1) return res.status(400).json({ message: 'No puedes quitarte admin si eres el único.' });
        }
        
        updates.push('role = ?');
        params.push(role);
    }

    if (updates.length === 0) {
        return res.json({ message: 'Sin cambios.' });
    }

    params.push(userId);
    const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
    db.prepare(sql).run(...params);

    res.json({ message: 'Usuario actualizado correctamente.' });

  } catch (err) {
    console.error('Error actualizando usuario:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// DELETE /api/admin/users/:id - Eliminar usuario y sus archivos
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  try {
    const userId = req.params.id;

    // No permitir que un admin se elimine a sí mismo
    if (userId === req.session.userId) {
      return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta desde el panel de administración.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    // Obtener archivos del usuario
    const userFiles = db.prepare('SELECT serverPath FROM files WHERE userId = ?').all(userId);

    // Eliminar archivos físicos
    let deletedFiles = 0;
    userFiles.forEach(file => {
      if (fs.existsSync(file.serverPath)) {
        try {
          fs.unlinkSync(file.serverPath);
          deletedFiles++;
        } catch (err) {
          console.error(`Error eliminando archivo ${file.serverPath}:`, err);
        }
      }
    });

    // Eliminar registros de archivos
    db.prepare('DELETE FROM files WHERE userId = ?').run(userId);

    // Eliminar usuario
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);

    res.json({ 
      message: `Usuario ${user.username} eliminado exitosamente.`,
      deletedFiles
    });
  } catch (err) {
    console.error('Error eliminando usuario:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/admin/files - Obtener todos los archivos con filtros
app.get('/api/admin/files', requireAdmin, (req, res) => {
  try {
    const { search, userId, limit = 50, offset = 0 } = req.query;
    
    let query = `
      SELECT 
        f.id, f.originalName, f.size, f.mimeType, f.createdAt, 
        f.expiresAt, f.maxDownloads, f.downloadCount, f.userId,
        u.username, u.email
      FROM files f
      LEFT JOIN users u ON f.userId = u.id
      WHERE 1=1
    `;
    const params = [];

    if (search) {
      query += ` AND f.originalName LIKE ?`;
      params.push(`%${search}%`);
    }

    if (userId) {
      query += ` AND f.userId = ?`;
      params.push(userId);
    }

    query += ` ORDER BY f.createdAt DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(limit), parseInt(offset));

    const files = db.prepare(query).all(...params);
    const totalCount = db.prepare('SELECT COUNT(*) as count FROM files').get().count;

    res.json({ files, totalCount });
  } catch (err) {
    console.error('Error obteniendo archivos:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// DELETE /api/admin/files/:id - Eliminar cualquier archivo (admin)
app.delete('/api/admin/files/:id', requireAdmin, (req, res) => {
  try {
    const fileId = req.params.id;
    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);

    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    // Eliminar archivo físico
    if (fs.existsSync(file.serverPath)) {
      fs.unlinkSync(file.serverPath);
    }

    // Eliminar de la base de datos
    db.prepare('DELETE FROM files WHERE id = ?').run(fileId);

    res.json({ message: `Archivo ${file.originalName} eliminado exitosamente.` });
  } catch (err) {
    console.error('Error eliminando archivo:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/admin/analytics - Obtener datos para gráficos
app.get('/api/admin/analytics', requireAdmin, (req, res) => {
  try {
    // Archivos subidos por día (últimos 7 días)
    const uploadsPerDay = db.prepare(`
      SELECT 
        DATE(createdAt/1000, 'unixepoch') as date,
        COUNT(*) as count
      FROM files
      WHERE createdAt >= ?
      GROUP BY date
      ORDER BY date ASC
    `).all(Date.now() - (7 * 24 * 60 * 60 * 1000));

    // Descargas por día (últimos 7 días)
    const downloadsPerDay = db.prepare(`
      SELECT 
        DATE(createdAt/1000, 'unixepoch') as date,
        SUM(downloadCount) as count
      FROM files
      WHERE createdAt >= ?
      GROUP BY date
      ORDER BY date ASC
    `).all(Date.now() - (7 * 24 * 60 * 60 * 1000));

    // Archivos por tipo
    const filesByType = db.prepare(`
      SELECT 
        CASE 
          WHEN mimeType LIKE 'image/%' THEN 'Imágenes'
          WHEN mimeType LIKE 'video/%' THEN 'Videos'
          WHEN mimeType LIKE 'audio/%' THEN 'Audio'
          WHEN mimeType LIKE 'application/pdf' THEN 'PDFs'
          WHEN mimeType LIKE 'application/%' THEN 'Documentos'
          WHEN mimeType LIKE 'text/%' THEN 'Texto'
          ELSE 'Otros'
        END as type,
        COUNT(*) as count,
        SUM(size) as totalSize
      FROM files
      GROUP BY type
      ORDER BY count DESC
    `).all();

    // Top 10 archivos más descargados
    const topFiles = db.prepare(`
      SELECT 
        f.id, f.originalName, f.downloadCount, u.username
      FROM files f
      LEFT JOIN users u ON f.userId = u.id
      ORDER BY f.downloadCount DESC
      LIMIT 10
    `).all();

    // Usuarios más activos
    const topUsers = db.prepare(`
      SELECT 
        u.username, u.email,
        COUNT(f.id) as fileCount,
        SUM(f.downloadCount) as totalDownloads
      FROM users u
      LEFT JOIN files f ON u.id = f.userId
      GROUP BY u.id
      HAVING fileCount > 0
      ORDER BY fileCount DESC
      LIMIT 10
    `).all();

    res.json({
      uploadsPerDay,
      downloadsPerDay,
      filesByType,
      topFiles,
      topUsers
    });
  } catch (err) {
    console.error('Error obteniendo analíticas:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/settings/footer - Obtener configuración del footer (público)
app.get('/api/settings/footer', (req, res) => {
  try {
    const config = db.prepare('SELECT value FROM settings WHERE key = ?').get('footer_config');
    if (config) {
      res.json(JSON.parse(config.value));
    } else {
      // Fallback si no existe en DB (aunque debería por la inicialización)
      res.json({});
    }
  } catch (err) {
    console.error('Error obteniendo configuración del footer:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// PUT /api/admin/settings/footer - Actualizar configuración del footer (admin)
app.put('/api/admin/settings/footer', requireAdmin, (req, res) => {
  try {
    const newConfig = req.body;
    
    // Validación básica
    if (!newConfig || typeof newConfig !== 'object') {
      return res.status(400).json({ message: 'Configuración inválida.' });
    }

    db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('footer_config', JSON.stringify(newConfig));
    
    res.json({ message: 'Configuración del footer actualizada correctamente.' });
  } catch (err) {
    console.error('Error actualizando configuración del footer:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/admin/settings/branding/upload - Subir logo para branding (admin)
app.post('/api/admin/settings/branding/upload', requireAdmin, (req, res) => {
  uploadBranding(req, res, (err) => {
    if (err) {
      console.error('Error en subida de branding:', err);
      return res.status(400).json({ message: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'No se ha proporcionado ningún archivo.' });
    }

    // Devolver la URL pública
    // La carpeta BRANDING_PATH se sirve en /branding
    const url = `/branding/${req.file.filename}`;
    res.json({ url });
  });
});

// --- USER ENDPOINTS ---

// GET /api/user/files - Obtener archivos del usuario
app.get('/api/user/files', requireAuth, (req, res) => {
  try {
    const files = db.prepare(`
      SELECT id, originalName, size, createdAt, expiresAt, maxDownloads, downloadCount, mimeType
      FROM files 
      WHERE userId = ?
      ORDER BY createdAt DESC
    `).all(req.session.userId);

    res.json({ files });

  } catch (err) {
    console.error('Error al obtener archivos:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// DELETE /api/user/files/:id - Eliminar archivo del usuario
app.delete('/api/user/files/:id', requireAuth, (req, res) => {
  try {
    const file = db.prepare('SELECT * FROM files WHERE id = ? AND userId = ?').get(req.params.id, req.session.userId);

    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    // Eliminar archivo físico
    if (fs.existsSync(file.serverPath)) {
      fs.unlinkSync(file.serverPath);
    }

    // Eliminar de la base de datos
    db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);

    res.json({ message: 'Archivo eliminado con éxito.' });

  } catch (err) {
    console.error('Error al eliminar archivo:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/user/change-password - Cambiar contraseña
app.post('/api/user/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Todos los campos son requeridos.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'La nueva contraseña debe tener al menos 8 caracteres.' });
    }

    // Obtener usuario
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    // Verificar contraseña actual
    const isValid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ message: 'Contraseña actual incorrecta.' });
    }

    // Hashear nueva contraseña
    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    // Actualizar contraseña
    db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(newPasswordHash, req.session.userId);

    res.json({ message: 'Contraseña actualizada con éxito.' });

  } catch (err) {
    console.error('Error al cambiar contraseña:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// DELETE /api/user/account - Eliminar cuenta de usuario
app.delete('/api/user/account', requireAuth, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ message: 'La contraseña es requerida.' });
    }

    // Obtener usuario
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    // Verificar contraseña
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ message: 'Contraseña incorrecta.' });
    }

    // Obtener todos los archivos del usuario
    const userFiles = db.prepare('SELECT serverPath FROM files WHERE userId = ?').all(req.session.userId);

    // Eliminar archivos físicos del sistema
    userFiles.forEach(file => {
      if (fs.existsSync(file.serverPath)) {
        try {
          fs.unlinkSync(file.serverPath);
        } catch (err) {
          console.error(`Error eliminando archivo ${file.serverPath}:`, err);
        }
      }
    });

    // Eliminar registros de archivos de la base de datos
    db.prepare('DELETE FROM files WHERE userId = ?').run(req.session.userId);

    // Eliminar usuario de la base de datos
    db.prepare('DELETE FROM users WHERE id = ?').run(req.session.userId);

    // Destruir sesión
    req.session.destroy();

    res.json({ message: 'Cuenta eliminada exitosamente.' });

  } catch (err) {
    console.error('Error al eliminar cuenta:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/user/update-profile - Actualizar email y/o nombre de usuario
app.post('/api/user/update-profile', requireAuth, async (req, res) => {
  try {
    const { email, username } = req.body || {};
    const userId = req.session.userId;

    if (!email && !username) {
      return res.status(400).json({ message: 'Debes proporcionar email y/o nombre de usuario.' });
    }

    // Obtener usuario actual
    const current = db.prepare('SELECT id, email, username FROM users WHERE id = ?').get(userId);
    if (!current) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    const updates = {};

    // Validar y preparar email si cambia
    if (typeof email === 'string' && email.trim() !== '' && email.trim() !== current.email) {
      const normalizedEmail = email.trim();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(normalizedEmail)) {
        return res.status(400).json({ message: 'El email no es válido.' });
      }
      const existingEmail = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(normalizedEmail, userId);
      if (existingEmail) {
        return res.status(409).json({ message: 'Este email ya está en uso.' });
      }
      updates.email = normalizedEmail;
    }

    // Validar y preparar username si cambia
    if (typeof username === 'string' && username.trim() !== '' && username.trim() !== current.username) {
      const normalizedUsername = username.trim();
      if (normalizedUsername.length < 3) {
        return res.status(400).json({ message: 'El nombre de usuario debe tener al menos 3 caracteres.' });
      }
      const existingUsername = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(normalizedUsername, userId);
      if (existingUsername) {
        return res.status(409).json({ message: 'Este nombre de usuario ya está en uso.' });
      }
      updates.username = normalizedUsername;
    }

    if (!updates.email && !updates.username) {
      return res.status(400).json({ message: 'No hay cambios para actualizar.' });
    }

    // Construir consulta dinámica
    const fields = [];
    const values = [];
    if (updates.email) { fields.push('email = ?'); values.push(updates.email); }
    if (updates.username) { fields.push('username = ?'); values.push(updates.username); }
    values.push(userId);

    const sql = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
    db.prepare(sql).run(...values);

    // Actualizar sesión si cambió username
    if (updates.username) {
      req.session.username = updates.username;
    }

    const updated = db.prepare('SELECT id, email, username FROM users WHERE id = ?').get(userId);
    return res.json({ message: 'Perfil actualizado con éxito.', user: updated });

  } catch (err) {
    console.error('Error al actualizar perfil:', err);
    return res.status(500).json({ message: 'Error del servidor.' });
  }
});

// --- FILE ENDPOINTS ---

// POST /api/upload - Subida de archivos
app.post('/api/upload', detectOrigin, (req, res) => {
  upload(req, res, (err) => {
    if (err) {
      console.error('Error en Multer:', err);
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ message: 'El archivo excede el tamaño máximo permitido.' });
      }
      return res.status(500).json({ message: 'Error al subir el archivo.', error: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'No se ha proporcionado ningún archivo.' });
    }

    try {
      const { password, expires, maxDownloads } = req.body;
      
      // Forzar expiración máxima de 15 días (360 horas)
      const MAX_EXPIRY_DAYS = 15;
      const MAX_EXPIRY_HOURS = MAX_EXPIRY_DAYS * 24; // 360 horas
      
      let expiresHours = expires && !isNaN(parseInt(expires)) ? parseInt(expires) : MAX_EXPIRY_HOURS;
      // Clampear a máximo 15 días
      if (expiresHours > MAX_EXPIRY_HOURS || expiresHours <= 0) {
        expiresHours = MAX_EXPIRY_HOURS;
      }
      const expiresAt = Date.now() + (expiresHours * 60 * 60 * 1000);

      const fileData = {
        id: uuidv4(),
        originalName: req.file.originalname,
        serverPath: req.file.path,
        mimeType: req.file.mimetype,
        size: req.file.size,
        createdAt: Date.now(),
        expiresAt: expiresAt, // Almacenado como timestamp
        maxDownloads: maxDownloads ? parseInt(maxDownloads) : null,
        downloadCount: 0,
        passwordHash: hashPassword(password),
        userId: req.session.userId || null // Asociar con usuario si está autenticado
      };

      // Guardar metadata en SQLite
      const stmt = db.prepare(`
        INSERT INTO files (id, originalName, serverPath, mimeType, size, createdAt, expiresAt, maxDownloads, passwordHash, userId)
        VALUES (@id, @originalName, @serverPath, @mimeType, @size, @createdAt, @expiresAt, @maxDownloads, @passwordHash, @userId)
      `);
      stmt.run(fileData);

      // Generar URL de descarga basada en el origen detectado
      const fallbackOrigin = stripTrailingSlash(`${req.protocol}://${req.get('host') || req.hostname || 'localhost'}`);
      const downloadOrigin = req.downloadOrigin || stripTrailingSlash(process.env.PUBLIC_ORIGIN) || stripTrailingSlash(process.env.LOCAL_ORIGIN) || fallbackOrigin;
      const downloadUrl = `${downloadOrigin}/share/${fileData.id}`;
      
      res.status(201).json({
        message: 'Archivo subido con éxito.',
        downloadUrl: downloadUrl,
        id: fileData.id,
        detectedOrigin: req.originType
      });

    } catch (dbError) {
      console.error('Error en DB:', dbError);
      // Si falla la DB, borrar el archivo subido para no dejar huérfanos
      fs.unlinkSync(req.file.path);
      res.status(500).json({ message: 'Error al guardar la metadata del archivo.' });
    }
  });
});

// --- CHUNKED UPLOAD ENDPOINTS ---

// POST /api/upload/init - inicia una subida por chunks
app.post('/api/upload/init', async (req, res) => {
  try {
    const { fileName, size, mimeType, expires, maxDownloads, password } = req.body || {};
    if (!fileName || !size) {
      return res.status(400).json({ message: 'fileName y size son obligatorios.' });
    }

    // Verificar cuota de usuario (100GB)
    if (req.session.userId) {
      const USER_QUOTA = 100 * 1024 * 1024 * 1024; // 100GB
      const currentUsage = db.prepare('SELECT SUM(size) as total FROM files WHERE userId = ?').get(req.session.userId).total || 0;
      
      if (currentUsage + Number(size) > USER_QUOTA) {
        return res.status(413).json({ message: 'Has excedido tu cuota de almacenamiento de 100GB.' });
      }
    }

    const uploadId = uuidv4();
    const chunkSize = 10 * 1024 * 1024; // 10MB (Optimizado para Cloudflare Free Tier)
    const totalChunks = Math.ceil(Number(size) / chunkSize);

    const dir = path.join(CHUNKS_PATH, uploadId);
    fs.mkdirSync(dir, { recursive: true });

    // Forzar expiración máxima de 15 días (360 horas)
    const MAX_EXPIRY_DAYS = 15;
    const MAX_EXPIRY_HOURS = MAX_EXPIRY_DAYS * 24; // 360 horas
    
    let expiresHours = expires && !isNaN(parseInt(expires)) ? parseInt(expires) : MAX_EXPIRY_HOURS;
    // Clampear a máximo 15 días
    if (expiresHours > MAX_EXPIRY_HOURS || expiresHours <= 0) {
      expiresHours = MAX_EXPIRY_HOURS;
    }

    const meta = {
      uploadId,
      fileName,
      size: Number(size),
      mimeType: mimeType || 'application/octet-stream',
      createdAt: Date.now(),
      expiresHours: expiresHours,
      maxDownloads: maxDownloads ? parseInt(maxDownloads) : null,
      passwordHash: hashPassword(password),
      totalChunks,
      chunkSize
    };
    fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(meta));

    res.status(201).json({ uploadId, chunkSize, totalChunks, received: [] });
  } catch (err) {
    console.error('Error en /api/upload/init:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/upload/chunk?uploadId=...&index=...&total=...
// Body: binario (application/octet-stream) del chunk
app.post('/api/upload/chunk', (req, res) => {
  try {
    const { uploadId, index } = req.query;
    if (!uploadId || typeof index === 'undefined') {
      return res.status(400).json({ message: 'uploadId e index son obligatorios.' });
    }
    const idx = parseInt(index);
    const dir = path.join(CHUNKS_PATH, uploadId);
    const metaPath = path.join(dir, 'meta.json');
    if (!fs.existsSync(dir) || !fs.existsSync(metaPath)) {
      return res.status(404).json({ message: 'Subida no encontrada.' });
    }

    const partPath = path.join(dir, `${idx}.part`);
    const writeStream = fs.createWriteStream(partPath);
    req.pipe(writeStream);
    writeStream.on('finish', () => {
      res.json({ ok: true, index: idx });
    });
    writeStream.on('error', (err) => {
      console.error('Error escribiendo chunk:', err);
      res.status(500).json({ message: 'Error al guardar el chunk.' });
    });
  } catch (err) {
    console.error('Error en /api/upload/chunk:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/upload/status
app.get('/api/upload/status', (req, res) => {
  try {
    const { uploadId } = req.query;
    if (!uploadId) return res.status(400).json({ message: 'uploadId es obligatorio.' });
    const dir = path.join(CHUNKS_PATH, uploadId);
    const metaPath = path.join(dir, 'meta.json');
    if (!fs.existsSync(dir) || !fs.existsSync(metaPath)) {
      return res.status(404).json({ message: 'Subida no encontrada.' });
    }
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.part'));
    const received = files.map(f => parseInt(f.replace('.part',''))).sort((a,b)=>a-b);
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    res.json({ uploadId, received, totalChunks: meta.totalChunks, chunkSize: meta.chunkSize });
  } catch (err) {
    console.error('Error en /api/upload/status:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/upload/complete - ensambla los chunks y crea el registro
app.post('/api/upload/complete', detectOrigin, async (req, res) => {
  let finalPath;
  try {
    const { uploadId } = req.body || {};
    if (!uploadId) return res.status(400).json({ message: 'uploadId es obligatorio.' });
    const dir = path.join(CHUNKS_PATH, uploadId);
    const metaPath = path.join(dir, 'meta.json');
    if (!fs.existsSync(dir) || !fs.existsSync(metaPath)) {
      return res.status(404).json({ message: 'Subida no encontrada.' });
    }
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));

    // Verificar que todos los chunks existen
    const missing = [];
    for (let i = 0; i < meta.totalChunks; i++) {
      if (!fs.existsSync(path.join(dir, `${i}.part`))) missing.push(i);
    }
    if (missing.length) {
      return res.status(400).json({ message: 'Faltan chunks.', missing });
    }

    // Ensamblar archivo final de forma secuencial para evitar errores de writev
    const uniqueName = `${uuidv4()}${path.extname(meta.fileName)}`;
    finalPath = path.join(STORAGE_PATH, uniqueName);

    const finalHandle = await fsp.open(finalPath, 'w');
    try {
      for (let i = 0; i < meta.totalChunks; i++) {
        const partPath = path.join(dir, `${i}.part`);
        const data = await fsp.readFile(partPath);
        await finalHandle.write(data);
      }
    } finally {
      await finalHandle.close();
    }

    const fileSize = (await fsp.stat(finalPath)).size;
    const expiresAt = meta.expiresHours ? (Date.now() + (meta.expiresHours * 60 * 60 * 1000)) : null;

    const fileData = {
      id: uuidv4(),
      originalName: meta.fileName,
      serverPath: finalPath,
      mimeType: meta.mimeType,
      size: fileSize,
      createdAt: Date.now(),
      expiresAt,
      maxDownloads: meta.maxDownloads,
      downloadCount: 0,
      passwordHash: meta.passwordHash,
      userId: req.session?.userId || null
    };

    const stmt = db.prepare(`
      INSERT INTO files (id, originalName, serverPath, mimeType, size, createdAt, expiresAt, maxDownloads, passwordHash, userId)
      VALUES (@id, @originalName, @serverPath, @mimeType, @size, @createdAt, @expiresAt, @maxDownloads, @passwordHash, @userId)
    `);
    stmt.run(fileData);

    // Limpiar carpeta de chunks
    try {
      fs.readdirSync(dir).forEach(f => fs.unlinkSync(path.join(dir, f)));
      fs.rmdirSync(dir);
    } catch (e) {
      console.warn('No se pudo limpiar carpeta de chunks:', e.message);
    }

    const fallbackOrigin = stripTrailingSlash(`${req.protocol}://${req.get('host') || req.hostname || 'localhost'}`);
    const downloadOrigin = req.downloadOrigin || stripTrailingSlash(process.env.PUBLIC_ORIGIN) || stripTrailingSlash(process.env.LOCAL_ORIGIN) || fallbackOrigin;
    const downloadUrl = `${downloadOrigin}/share/${fileData.id}`;
    return res.json({ message: 'Subida completada.', id: fileData.id, downloadUrl, detectedOrigin: req.originType });

  } catch (err) {
    console.error('Error en /api/upload/complete:', err);
    if (finalPath && fs.existsSync(finalPath)) {
      try {
        fs.unlinkSync(finalPath);
      } catch (cleanupErr) {
        console.warn('No se pudo eliminar archivo incompleto:', cleanupErr.message);
      }
    }
    return res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/meta/:id - Obtener metadata pública de un archivo
app.get('/api/meta/:id', (req, res) => {
  try {
    const stmt = db.prepare('SELECT id, originalName, size, expiresAt, maxDownloads, downloadCount, passwordHash FROM files WHERE id = ?');
    const file = stmt.get(req.params.id);

    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    // Comprobar expiración por tiempo
    if (file.expiresAt && file.expiresAt < Date.now()) {
      return res.status(410).json({ message: 'Este enlace ha expirado.' });
    }

    // Comprobar límite de descargas
    if (file.maxDownloads && file.downloadCount >= file.maxDownloads) {
      return res.status(410).json({ message: 'Se ha alcanzado el límite de descargas.' });
    }

    // No enviar el hash de la contraseña, solo si requiere una
    res.json({
      id: file.id,
      fileName: file.originalName,
      size: file.size,
      requiresPassword: !!file.passwordHash,
      mimeType: file.mimeType, // Enviar mimeType para previews
      // Opcional: enviar cuándo expira o cuántas descargas quedan
      expiresAt: file.expiresAt,
      downloadsLeft: file.maxDownloads ? file.maxDownloads - file.downloadCount : null
    });

  } catch (err) {
    console.error('Error al obtener metadata:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/preview/:id - Obtener vista previa de imagen
app.get('/api/preview/:id', (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM files WHERE id = ?');
    const file = stmt.get(req.params.id);

    if (!file) {
      return res.status(404).send('Archivo no encontrado');
    }

    // Solo permitir imágenes
    if (!file.mimeType.startsWith('image/')) {
      return res.status(400).send('Vista previa no disponible');
    }

    // Comprobar si el archivo existe
    if (!fs.existsSync(file.serverPath)) {
      return res.status(404).send('Archivo físico no encontrado');
    }

    // Servir el archivo
    res.setHeader('Content-Type', file.mimeType);
    // Cachear por 1 hora
    res.setHeader('Cache-Control', 'public, max-age=3600');
    fs.createReadStream(file.serverPath).pipe(res);

  } catch (err) {
    console.error('Error en preview:', err);
    res.status(500).send('Error del servidor');
  }
});

// POST /api/download/:id - Iniciar la descarga (con chequeo de contraseña)
app.post('/api/download/:id', (req, res) => {
  try {
    const expectsJson =
      req.get('x-download-check') === 'true' ||
      (req.headers.accept && req.headers.accept.includes('application/json'));

    const stmt = db.prepare('SELECT * FROM files WHERE id = ?');
    const file = stmt.get(req.params.id);

    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    // Comprobar expiración por tiempo
    if (file.expiresAt && file.expiresAt < Date.now()) {
      return res.status(410).json({ message: 'Este enlace ha expirado.' });
    }

    // Comprobar límite de descargas
    if (file.maxDownloads && file.downloadCount >= file.maxDownloads) {
      return res.status(410).json({ message: 'Se ha alcanzado el límite de descargas.' });
    }

    // Comprobar contraseña
    if (file.passwordHash) {
      const { password } = req.body;
      if (!password || hashPassword(password) !== file.passwordHash) {
        return res.status(401).json({ message: 'Contraseña incorrecta.' });
      }
    }

    if (expectsJson) {
      return res.json({ ok: true });
    }

    // Incrementar contador de descargas
    const updateStmt = db.prepare('UPDATE files SET downloadCount = downloadCount + 1 WHERE id = ?');
    updateStmt.run(req.params.id);

    // Enviar el archivo
    res.download(file.serverPath, file.originalName, (err) => {
      if (err) {
        console.error('Error al enviar archivo:', err);
        // No se puede enviar un status 500 si la respuesta ya empezó
      }
    });

  } catch (err) {
    console.error('Error en descarga:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// DELETE /api/files/:id - Eliminar archivo sin autenticación (para archivos recién subidos)
app.delete('/api/files/:id', (req, res) => {
  try {
    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);

    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }
    
    // Solo permitir eliminar archivos sin userId (subidos sin cuenta) 
    // o si el userId coincide con la sesión actual
    if (file.userId && file.userId !== req.session?.userId) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar este archivo.' });
    }

    // Eliminar archivo físico
    if (fs.existsSync(file.serverPath)) {
      fs.unlinkSync(file.serverPath);
    }

    // Eliminar de la base de datos
    db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);

    res.json({ message: 'Archivo eliminado con éxito.' });

  } catch (err) {
    console.error('Error al eliminar archivo:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/report/:fileId - Reportar un archivo
app.post('/api/report/:fileId', (req, res) => {
  try {
    const { reason } = req.body;
    const fileId = req.params.id; // Corregido: req.params.fileId no existe en la ruta definida como :fileId.
    // Express mapea :fileId a req.params.fileId.
    // Corrección: usar req.params.fileId
    
    if (!reason) {
      return res.status(400).json({ message: 'El motivo es obligatorio.' });
    }

    const file = db.prepare('SELECT id FROM files WHERE id = ?').get(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: 'Archivo no encontrado.' });
    }

    const reportId = uuidv4();
    db.prepare('INSERT INTO reports (id, fileId, reason, createdAt) VALUES (?, ?, ?, ?)').run(reportId, req.params.fileId, reason, Date.now());

    res.json({ message: 'Reporte enviado correctamente.' });
  } catch (err) {
    console.error('Error enviando reporte:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// GET /api/admin/reports - Obtener reportes (admin)
app.get('/api/admin/reports', requireAdmin, (req, res) => {
  try {
    const reports = db.prepare(`
      SELECT r.id, r.reason, r.createdAt, r.status, f.id as fileId, f.originalName, f.size
      FROM reports r
      LEFT JOIN files f ON r.fileId = f.id
      ORDER BY r.createdAt DESC
    `).all();
    res.json({ reports });
  } catch (err) {
    console.error('Error obteniendo reportes:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// POST /api/admin/reports/:id/resolve - Resolver reporte (admin)
app.post('/api/admin/reports/:id/resolve', requireAdmin, (req, res) => {
  try {
    const { action } = req.body; // 'dismiss' o 'delete_file'
    const reportId = req.params.id;

    const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(reportId);
    if (!report) return res.status(404).json({ message: 'Reporte no encontrado.' });

    if (action === 'delete_file') {
      const file = db.prepare('SELECT * FROM files WHERE id = ?').get(report.fileId);
      if (file) {
        if (fs.existsSync(file.serverPath)) {
          try { fs.unlinkSync(file.serverPath); } catch(e) {}
        }
        db.prepare('DELETE FROM files WHERE id = ?').run(file.id);
      }
      db.prepare('UPDATE reports SET status = ? WHERE id = ?').run('resolved_deleted', reportId);
      // También marcar otros reportes del mismo archivo como resueltos
      db.prepare('UPDATE reports SET status = ? WHERE fileId = ? AND id != ?').run('resolved_deleted', report.fileId, reportId);
    } else {
      db.prepare('UPDATE reports SET status = ? WHERE id = ?').run('dismissed', reportId);
    }

    res.json({ message: 'Reporte gestionado.' });
  } catch (err) {
    console.error('Error resolviendo reporte:', err);
    res.status(500).json({ message: 'Error del servidor.' });
  }
});

// --- Servir Frontend ---

// Servir la página de descarga
app.get('/share/:id', (req, res) => {
  // Esta ruta podría servir una página HTML específica (como index.html)
  // que luego use JS para llamar a /api/meta/:id
  res.sendFile(path.join(FRONTEND_PATH, 'index.html'));
});

// Servir la aplicación de frontend principal
app.use(express.static(FRONTEND_PATH));

// Servir assets estáticos (logos, favicons)
app.use('/assets', express.static(path.join(__dirname, '../assets')));
app.use('/branding', express.static(BRANDING_PATH));

// Compatibilidad: muchos navegadores solicitan /favicon.ico en la raíz
// Redirigimos a nuestro favicon SVG si no existe un .ico físico
app.get('/favicon.ico', (req, res) => {
  res.redirect(301, '/assets/icons/favicon.svg');
});

// Fallback para SPA (Single Page Application)
app.get('*', (req, res) => {
  res.sendFile(path.join(FRONTEND_PATH, 'index.html'));
});

// --- Limpieza automática de archivos expirados ---
function cleanupExpiredFiles() {
  try {
    const now = Date.now();
    const filesToClean = db.prepare(`
      SELECT id, serverPath, originalName
      FROM files
      WHERE (expiresAt IS NOT NULL AND expiresAt <= ?)
         OR (maxDownloads IS NOT NULL AND downloadCount >= maxDownloads)
    `).all(now);
    
    if (filesToClean.length > 0) {
      console.log(`🧹 Limpiando ${filesToClean.length} archivo(s) expirado(s) o con límite de descargas alcanzado...`);
      
      filesToClean.forEach(file => {
        // Seguridad: Verificar que el archivo esté dentro de STORAGE_PATH
        const safePath = path.resolve(file.serverPath);
        const storageRoot = path.resolve(STORAGE_PATH);
        
        if (!safePath.startsWith(storageRoot)) {
          console.error(`🚨 ALERTA DE SEGURIDAD: Intento de eliminar archivo fuera de uploads: ${file.serverPath}`);
          return;
        }

        // Eliminar archivo físico
        if (fs.existsSync(safePath)) {
          try {
            fs.unlinkSync(safePath);
            console.log(`  ✅ Eliminado: ${file.originalName}`);
          } catch (err) {
            console.error(`  ❌ Error eliminando archivo ${file.serverPath}:`, err.message);
          }
        }
        
        // Eliminar registro de la base de datos
        db.prepare('DELETE FROM files WHERE id = ?').run(file.id);
      });
      
      console.log(`✨ Limpieza completada.`);
    }
  } catch (err) {
    console.error('❌ Error en limpieza de archivos expirados:', err);
  }
}

// Ejecutar limpieza cada 15 minutos (900000 ms)
const CLEANUP_INTERVAL = 15 * 60 * 1000; // 15 minutos
setInterval(cleanupExpiredFiles, CLEANUP_INTERVAL);

// Ejecutar limpieza al iniciar el servidor
cleanupExpiredFiles();

// --- Iniciar Servidor ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sendu corriendo en http://0.0.0.0:${PORT}`);
  console.log(`Almacenamiento en: ${STORAGE_PATH}`);
  console.log(`Base de datos en: ${DB_PATH}`);
  console.log(`--- Orígenes configurados ---`);
  console.log(`LOCAL: ${process.env.LOCAL_ORIGIN}`);
  console.log(`PUBLIC: ${process.env.PUBLIC_ORIGIN}`);
  console.log(`🧹 Limpieza automática activa (cada ${CLEANUP_INTERVAL / 1000 / 60} minutos)`);
  console.log("Servidor listo.");
});
