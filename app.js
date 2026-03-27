const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');

// const logger = require('./utils/logger');
const { generalLimiter } = require('./rateLimiter');
const { notFound, errorHandler } = require('./errorHandler');

// ─── Route Imports ────────────────────────────────────────────────────────────
const authRoutes = require('./authRoutes');
const healthRoutes = require('./healthRoutes');

const app = express();

// ─── Trust Proxy (for Render.com / reverse proxy) ────────────────────────────
app.set('trust proxy', 1);

// ─── Security Middleware ──────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// ─── CORS ─────────────────────────────────────────────────────────────────────
const allowedOrigins = [
  process.env.FRONTEND_URL,
  process.env.APP_URL,
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:4200',
].filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, Postman, curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      // In development, allow all origins
      if (process.env.NODE_ENV !== 'production') return callback(null, true);
      callback(new Error(`CORS policy: Origin ${origin} not allowed.`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

// ─── HTTP Request Logger ──────────────────────────────────────────────────────
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ─── Body Parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ─── Sanitize MongoDB queries (prevent injection) ────────────────────────────
app.use(mongoSanitize());

// ─── Global Rate Limiter ──────────────────────────────────────────────────────
app.use('/api/', generalLimiter);

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/health', healthRoutes);
app.use('/api/auth', authRoutes);

// ─── Root Endpoint ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    name: 'AffiliateEngine API',
    version: '1.0.0',
    description: 'Backend API for AffiliateEngine platform',
    documentation: '/api/docs',
    health: '/health',
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        verifyEmail: 'POST /api/auth/verify-email',
        resendOTP: 'POST /api/auth/resend-otp',
        login: 'POST /api/auth/login',
        logout: 'POST /api/auth/logout',
        refreshToken: 'POST /api/auth/refresh-token',
        profile: 'GET /api/auth/me',
      },
    },
  });
});

// ─── Error Handling ───────────────────────────────────────────────────────────
app.use(notFound);
app.use(errorHandler);

module.exports = app;
