// ============================================================================
// TEST SUITE: NODE.JS/EXPRESS API (CLEAN CODE)
// Expected: Secure, robust, performant API implementation
// ============================================================================

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const app = express();

// GOOD: Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));  // Body size limit
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// GOOD: Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,  // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// GOOD: CORS configuration
const cors = require('cors');
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// GOOD: Request logging with sanitization
const morgan = require('morgan');
morgan.token('sanitized-body', (req) => {
  const body = { ...req.body };
  // Remove sensitive fields
  delete body.password;
  delete body.creditCard;
  delete body.apiKey;
  return JSON.stringify(body);
});

app.use(morgan(':method :url :status - :sanitized-body'));

// GOOD: Database connection pool
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 20,  // Maximum pool size
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// GOOD: Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: 'Database connection failed'
    });
  }
});

// GOOD: Input validation with parameterized queries
app.get('/api/users/:id',
  param('id').isInt().toInt(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { rows } = await pool.query(
        'SELECT id, name, email FROM users WHERE id = $1',
        [req.params.id]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json(rows[0]);
    } catch (error) {
      next(error);  // Pass to error handler
    }
  }
);

// GOOD: Async/await with proper error handling
app.post('/api/users',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).trim(),
    body('name').trim().isLength({ min: 1, max: 100 })
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, name } = req.body;
      const hashedPassword = await bcrypt.hash(password, 12);

      const { rows } = await pool.query(
        'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name',
        [email, hashedPassword, name]
      );

      res.status(201).json(rows[0]);
    } catch (error) {
      if (error.code === '23505') {  // Unique violation
        return res.status(409).json({ error: 'Email already exists' });
      }
      next(error);
    }
  }
);

// GOOD: Proper authentication middleware
const jwt = require('jsonwebtoken');

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE
    });

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    next(error);
  }
};

// GOOD: Login with rate limiting and secure password comparison
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,  // 5 attempts per 15 minutes
  skipSuccessfulRequests: true
});

app.post('/api/login',
  loginLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 1 })
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      const { rows } = await pool.query(
        'SELECT id, email, password_hash FROM users WHERE email = $1',
        [email]
      );

      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = rows[0];
      const validPassword = await bcrypt.compare(password, user.password_hash);

      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET,
        {
          algorithm: 'HS256',
          expiresIn: '24h',
          issuer: process.env.JWT_ISSUER,
          audience: process.env.JWT_AUDIENCE
        }
      );

      res.json({ token, userId: user.id });
    } catch (error) {
      next(error);
    }
  }
);

// GOOD: Async file operations with streaming
app.get('/api/download/:fileId',
  authMiddleware,
  param('fileId').isUUID(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { rows } = await pool.query(
        'SELECT filename, filepath FROM files WHERE id = $1 AND user_id = $2',
        [req.params.fileId, req.user.userId]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: 'File not found' });
      }

      const file = rows[0];

      // Check if file exists
      await fs.promises.access(file.filepath);

      // Stream file instead of loading into memory
      res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
      const stream = fs.createReadStream(file.filepath);
      stream.pipe(res);

      stream.on('error', (error) => {
        next(error);
      });
    } catch (error) {
      next(error);
    }
  }
);

// GOOD: Pagination and filtering
app.get('/api/users',
  authMiddleware,
  async (req, res, next) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = Math.min(parseInt(req.query.limit) || 20, 100);  // Max 100
      const offset = (page - 1) * limit;

      const { rows: users } = await pool.query(
        'SELECT id, name, email, created_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',
        [limit, offset]
      );

      const { rows: count } = await pool.query('SELECT COUNT(*) FROM users');
      const total = parseInt(count[0].count);

      res.json({
        users,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// GOOD: Comprehensive error handler
app.use((err, req, res, next) => {
  console.error('Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method,
    userId: req.user?.userId
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';

  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'Internal server error',
    ...(isDevelopment && { stack: err.stack })
  });
});

// GOOD: 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.url
  });
});

// GOOD: Graceful shutdown
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});

const gracefulShutdown = async (signal) => {
  console.log(`\nReceived ${signal}, starting graceful shutdown`);

  // Stop accepting new connections
  server.close(async () => {
    console.log('HTTP server closed');

    try {
      // Close database pool
      await pool.end();
      console.log('Database pool closed');

      process.exit(0);
    } catch (error) {
      console.error('Error during shutdown:', error);
      process.exit(1);
    }
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    console.error('Forcing shutdown after timeout');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// GOOD: Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // In production, you might want to exit and let process manager restart
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

module.exports = { app, server, pool };
