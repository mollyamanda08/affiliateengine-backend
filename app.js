'use strict';

// ============================================================
//  AffiliateEngine Backend — Single File Server
//  All logic: DB, Models, Email, OTP, JWT, Routes, Middleware
// ============================================================

require('dotenv').config();

const express        = require('express');
const mongoose       = require('mongoose');
const bcrypt         = require('bcryptjs');
const jwt            = require('jsonwebtoken');
const nodemailer     = require('nodemailer');
const crypto         = require('crypto');
const cors           = require('cors');
const helmet         = require('helmet');
const morgan         = require('morgan');
const cookieParser   = require('cookie-parser');
const mongoSanitize  = require('express-mongo-sanitize');
const rateLimit      = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston        = require('winston');
const path           = require('path');
const fs             = require('fs');

// ─────────────────────────────────────────────────────────────
//  SECTION 1 — LOGGER
// ─────────────────────────────────────────────────────────────

const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const { combine, timestamp, errors, json, colorize, printf } = winston.format;

const consoleFormat = printf(({ level, message, timestamp, stack }) =>
  stack
    ? `[${timestamp}] ${level}: ${message}\n${stack}`
    : `[${timestamp}] ${level}: ${message}`
);

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), errors({ stack: true }), json()),
  defaultMeta: { service: 'affiliateengine-api' },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880,
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 5242880,
      maxFiles: 5,
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: combine(colorize({ all: true }), timestamp({ format: 'HH:mm:ss' }), consoleFormat),
    })
  );
} else {
  logger.add(
    new winston.transports.Console({ format: combine(timestamp(), json()) })
  );
}

// ─────────────────────────────────────────────────────────────
//  SECTION 2 — DATABASE CONNECTION
// ─────────────────────────────────────────────────────────────

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      connectTimeoutMS: 10000,
      heartbeatFrequencyMS: 10000,
    });

    logger.info(`✅ MongoDB Connected: ${conn.connection.host}`);

    mongoose.connection.on('error',        (err) => logger.error(`MongoDB error: ${err.message}`));
    mongoose.connection.on('disconnected', ()    => logger.warn('MongoDB disconnected. Reconnecting...'));
    mongoose.connection.on('reconnected',  ()    => logger.info('MongoDB reconnected.'));

    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('MongoDB connection closed.');
      process.exit(0);
    });
  } catch (err) {
    logger.error(`❌ MongoDB connection failed: ${err.message}`);
    process.exit(1);
  }
};

// ─────────────────────────────────────────────────────────────
//  SECTION 3 — USER MODEL
// ─────────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      minlength: [2, 'First name must be at least 2 characters'],
      maxlength: [50, 'First name cannot exceed 50 characters'],
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      minlength: [2, 'Last name must be at least 2 characters'],
      maxlength: [50, 'Last name cannot exceed 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },

    // ── Email Verification ──
    isEmailVerified:              { type: Boolean, default: false },
    emailVerificationOTP:         { type: String,  select: false },
    emailVerificationOTPExpires:  { type: Date,    select: false },
    emailVerificationAttempts:    { type: Number,  default: 0, select: false },

    // ── Account ──
    role:     { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' },
    isActive: { type: Boolean, default: true },
    isBanned: { type: Boolean, default: false },

    // ── Session ──
    lastLoginAt:   { type: Date },
    lastLoginIP:   { type: String },
    loginCount:    { type: Number, default: 0 },
    refreshTokens: { type: [String], select: false, default: [] },
  },
  { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
);

userSchema.virtual('fullName').get(function () {
  return `${this.firstName} ${this.lastName}`;
});

userSchema.index({ email: 1 });
userSchema.index({ createdAt: -1 });

// Hash password before save
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare plain password to hashed
userSchema.methods.comparePassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

// Return safe user object (no sensitive fields)
userSchema.methods.toSafeObject = function () {
  return {
    id:              this._id,
    firstName:       this.firstName,
    lastName:        this.lastName,
    fullName:        this.fullName,
    email:           this.email,
    role:            this.role,
    isEmailVerified: this.isEmailVerified,
    isActive:        this.isActive,
    lastLoginAt:     this.lastLoginAt,
    loginCount:      this.loginCount,
    createdAt:       this.createdAt,
    updatedAt:       this.updatedAt,
  };
};

// Find by email AND include password field
userSchema.statics.findByEmailWithPassword = function (email) {
  return this.findOne({ email: email.toLowerCase() }).select('+password');
};

const User = mongoose.model('User', userSchema);

// ─────────────────────────────────────────────────────────────
//  SECTION 4 — OTP UTILITIES
// ─────────────────────────────────────────────────────────────

const generateOTP = (length = 6) => {
  const max = Math.pow(10, length);
  const min = Math.pow(10, length - 1);
  return crypto.randomInt(min, max).toString().padStart(length, '0');
};

const generateOTPExpiry = (minutes = 10) => {
  const d = new Date();
  d.setMinutes(d.getMinutes() + minutes);
  return d;
};

const isOTPExpired = (expiresAt) => new Date() > new Date(expiresAt);

// ─────────────────────────────────────────────────────────────
//  SECTION 5 — EMAIL TEMPLATES
// ─────────────────────────────────────────────────────────────

const baseLayout = (content) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>AffiliateEngine</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f4f6f9;color:#333}
    .wrapper{max-width:600px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)}
    .header{background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:36px 40px;text-align:center}
    .header h1{color:#fff;font-size:28px;font-weight:700;letter-spacing:-.5px}
    .header p{color:rgba(255,255,255,.85);font-size:14px;margin-top:6px}
    .body{padding:40px 40px 30px}
    .body h2{font-size:22px;color:#1e1e2e;margin-bottom:12px}
    .body p{font-size:15px;color:#555;line-height:1.7;margin-bottom:16px}
    .otp-box{background:linear-gradient(135deg,#f0f0ff,#f8f0ff);border:2px dashed #a78bfa;border-radius:10px;padding:24px;text-align:center;margin:24px 0}
    .otp-code{font-size:42px;font-weight:800;letter-spacing:12px;color:#6366f1;font-family:'Courier New',monospace}
    .otp-meta{font-size:13px;color:#888;margin-top:10px}
    .alert-box{background:#fff8e1;border-left:4px solid #ffc107;border-radius:6px;padding:14px 18px;margin:20px 0;font-size:13px;color:#7a6200}
    .btn{display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600;margin:10px 0}
    hr{border:none;border-top:1px solid #eee;margin:28px 0}
    .footer{background:#f9fafc;padding:24px 40px;text-align:center;font-size:12px;color:#aaa}
    .footer a{color:#6366f1;text-decoration:none}
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      <h1>🚀 AffiliateEngine</h1>
      <p>Grow smarter. Earn faster.</p>
    </div>
    <div class="body">${content}</div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} AffiliateEngine. All rights reserved.</p>
      <p style="margin-top:8px">If you didn't request this, <a href="#">contact support</a>.</p>
    </div>
  </div>
</body>
</html>`;

const otpEmailTemplate = ({ name, otp, expiresInMinutes = 10 }) =>
  baseLayout(`
    <h2>Verify your email address 📬</h2>
    <p>Hi <strong>${name}</strong>,</p>
    <p>Thanks for registering! Use the code below to verify your email:</p>
    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-meta">⏰ Expires in <strong>${expiresInMinutes} minutes</strong></div>
    </div>
    <div class="alert-box">🔒 <strong>Never share this code.</strong> AffiliateEngine staff will never ask for it.</div>
    <p>If you didn't create an account, ignore this email.</p>
  `);

const welcomeEmailTemplate = ({ name, appUrl }) =>
  baseLayout(`
    <h2>Welcome to AffiliateEngine! 🎉</h2>
    <p>Hi <strong>${name}</strong>,</p>
    <p>Your email has been verified. You're now a member of AffiliateEngine!</p>
    <p style="text-align:center;margin:28px 0">
      <a href="${appUrl}" class="btn">Get Started Now →</a>
    </p>
    <hr/>
    <p><strong>What's next:</strong></p>
    <p>✅ Complete your profile<br/>📊 Set up your first campaign<br/>💰 Connect your payout method<br/>🔗 Start sharing affiliate links</p>
  `);

const resendOtpTemplate = ({ name, otp, expiresInMinutes = 10 }) =>
  baseLayout(`
    <h2>New Verification Code 🔄</h2>
    <p>Hi <strong>${name}</strong>,</p>
    <p>Here is your new OTP. Your previous code has been invalidated.</p>
    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-meta">⏰ Expires in <strong>${expiresInMinutes} minutes</strong></div>
    </div>
    <div class="alert-box">🔒 <strong>Never share this code</strong> with anyone.</div>
  `);

// ─────────────────────────────────────────────────────────────
//  SECTION 6 — EMAIL SERVICE (NODEMAILER)
// ─────────────────────────────────────────────────────────────

let _transporter = null;

const getTransporter = () => {
  if (_transporter) return _transporter;

  _transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
    pool: true,
    maxConnections: 5,
    maxMessages: 100,
    tls: { rejectUnauthorized: true },
  });

  _transporter.verify((err) => {
    if (err) logger.error(`Email service error: ${err.message}`);
    else     logger.info('✅ Gmail SMTP is ready.');
  });

  return _transporter;
};

const sendEmail = async ({ to, subject, html, text }) => {
  const transport = getTransporter();
  const info = await transport.sendMail({
    from: `"${process.env.EMAIL_FROM_NAME || 'AffiliateEngine'}" <${process.env.GMAIL_USER}>`,
    to, subject, html,
    text: text || 'Please view this email in an HTML-capable client.',
  });
  logger.info(`📧 Email sent to ${to} | ID: ${info.messageId}`);
  return info;
};

const sendOTPEmail = ({ to, name, otp }) => {
  const mins = parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10);
  return sendEmail({
    to,
    subject: `${otp} is your AffiliateEngine verification code`,
    html: otpEmailTemplate({ name, otp, expiresInMinutes: mins }),
    text: `Your AffiliateEngine OTP is: ${otp}. Expires in ${mins} minutes.`,
  });
};

const sendWelcomeEmail = ({ to, name }) =>
  sendEmail({
    to,
    subject: `Welcome to AffiliateEngine, ${name}! 🎉`,
    html: welcomeEmailTemplate({ name, appUrl: process.env.APP_URL || 'https://affiliateengine.com' }),
    text: `Welcome ${name}! Your account is verified.`,
  });

const sendResendOTPEmail = ({ to, name, otp }) => {
  const mins = parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10);
  return sendEmail({
    to,
    subject: `Your new AffiliateEngine verification code`,
    html: resendOtpTemplate({ name, otp, expiresInMinutes: mins }),
    text: `Your new AffiliateEngine OTP is: ${otp}. Expires in ${mins} minutes.`,
  });
};

// ─────────────────────────────────────────────────────────────
//  SECTION 7 — JWT HELPERS
// ─────────────────────────────────────────────────────────────

const generateAccessToken = (userId) =>
  jwt.sign(
    { id: userId, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d', issuer: 'affiliateengine', audience: 'affiliateengine-client' }
  );

const generateRefreshToken = (userId) =>
  jwt.sign(
    { id: userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d', issuer: 'affiliateengine', audience: 'affiliateengine-client' }
  );

const setTokenCookies = (res, accessToken, refreshToken) => {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('accessToken', accessToken, {
    httpOnly: true, secure: isProd, sameSite: isProd ? 'strict' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true, secure: isProd, sameSite: isProd ? 'strict' : 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, path: '/api/auth/refresh-token',
  });
};

// ─────────────────────────────────────────────────────────────
//  SECTION 8 — API RESPONSE HELPER
// ─────────────────────────────────────────────────────────────

const ok = (res, statusCode = 200, message = 'Success', data = {}) =>
  res.status(statusCode).json({ success: true, message, data, timestamp: new Date().toISOString() });

const fail = (res, statusCode = 500, message = 'Internal Server Error', errors = null) => {
  const body = { success: false, message, timestamp: new Date().toISOString() };
  if (errors) body.errors = errors;
  return res.status(statusCode).json(body);
};

// ─────────────────────────────────────────────────────────────
//  SECTION 9 — MIDDLEWARE
// ─────────────────────────────────────────────────────────────

const validateRequest = (req, res, next) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) {
    const formatted = errs.array().map((e) => ({ field: e.path, message: e.msg, value: e.value }));
    return fail(res, 422, 'Validation failed. Please check your input.', formatted);
  }
  next();
};

const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }
    if (!token) return fail(res, 401, 'Access denied. No token provided.');

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      if (e.name === 'TokenExpiredError') return fail(res, 401, 'Token has expired. Please log in again.');
      if (e.name === 'JsonWebTokenError') return fail(res, 401, 'Invalid token. Please log in again.');
      throw e;
    }

    const user = await User.findById(decoded.id).select('-password');
    if (!user)                           return fail(res, 401, 'User no longer exists.');
    if (!user.isActive || user.isBanned) return fail(res, 403, 'Account suspended. Contact support.');

    req.user = user;
    next();
  } catch (err) {
    logger.error(`Auth middleware error: ${err.message}`);
    return fail(res, 500, 'Authentication error.');
  }
};

const requireEmailVerified = (req, res, next) => {
  if (!req.user.isEmailVerified)
    return fail(res, 403, 'Email verification required to access this resource.');
  next();
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role))
    return fail(res, 403, `Access denied. Required roles: ${roles.join(', ')}`);
  next();
};

const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => fail(res, 429, 'Too many requests. Try again after 15 minutes.'),
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '10', 10),
  standardHeaders: true, legacyHeaders: false, skipSuccessfulRequests: true,
  handler: (req, res) => fail(res, 429, 'Too many auth attempts. Wait 15 minutes.'),
});

const otpResendLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 3,
  standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => fail(res, 429, 'Too many OTP requests. Wait 5 minutes.'),
});

const errorHandler = (err, req, res, next) => {
  let statusCode = err.statusCode || err.status || 500;
  let message    = err.message || 'Internal Server Error';

  if (err.name === 'ValidationError') {
    statusCode = 400;
    const errs = Object.values(err.errors).map((e) => ({ field: e.path, message: e.message }));
    return fail(res, statusCode, 'Validation failed', errs);
  }
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0];
    return fail(res, 409, `An account with this ${field || 'value'} already exists.`);
  }
  if (err.name === 'CastError')         { statusCode = 400; message = `Invalid ${err.path}: ${err.value}`; }
  if (err.name === 'JsonWebTokenError') { statusCode = 401; message = 'Invalid token.'; }
  if (err.name === 'TokenExpiredError') { statusCode = 401; message = 'Token expired.'; }

  if (statusCode >= 500) {
    logger.error(`[${statusCode}] ${message}`, { method: req.method, url: req.originalUrl, stack: err.stack });
  } else {
    logger.warn(`[${statusCode}] ${message} | ${req.method} ${req.originalUrl}`);
  }

  const extra = process.env.NODE_ENV !== 'production' ? { stack: err.stack } : null;
  return fail(res, statusCode, message, extra);
};

// ─────────────────────────────────────────────────────────────
//  SECTION 10 — VALIDATION CHAINS
// ─────────────────────────────────────────────────────────────

const registerValidation = [
  body('firstName').trim().notEmpty().withMessage('First name is required.')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters.'),
  body('lastName').trim().notEmpty().withMessage('Last name is required.')
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters.'),
  body('email').trim().notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Please provide a valid email.').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required.')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must include uppercase, lowercase, and a number.'),
];

const verifyEmailValidation = [
  body('email').trim().notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Invalid email.').normalizeEmail(),
  body('otp').trim().notEmpty().withMessage('OTP is required.')
    .isLength({ min: 6, max: 6 }).withMessage('OTP must be exactly 6 digits.')
    .isNumeric().withMessage('OTP must contain only numbers.'),
];

const resendOTPValidation = [
  body('email').trim().notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Invalid email.').normalizeEmail(),
];

const loginValidation = [
  body('email').trim().notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Invalid email.').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required.'),
];

// ─────────────────────────────────────────────────────────────
//  SECTION 11 — ROUTE HANDLERS
// ─────────────────────────────────────────────────────────────

// POST /api/auth/register
const handleRegister = async (req, res, next) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      if (existing.isEmailVerified)
        return fail(res, 409, 'An account with this email already exists. Please log in.');

      const otp    = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
      const expiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));
      existing.emailVerificationOTP        = otp;
      existing.emailVerificationOTPExpires = expiry;
      existing.emailVerificationAttempts   = 0;
      await existing.save();

      try { await sendOTPEmail({ to: existing.email, name: existing.firstName, otp }); }
      catch (e) { logger.error(`OTP resend failed: ${e.message}`); }

      return ok(res, 200, 'Account exists but unverified. New OTP sent to your email.', {
        email: existing.email, requiresVerification: true,
      });
    }

    const otp    = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
    const expiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));

    const user = await User.create({
      firstName, lastName, email, password,
      emailVerificationOTP: otp,
      emailVerificationOTPExpires: expiry,
    });

    try { await sendOTPEmail({ to: user.email, name: user.firstName, otp }); }
    catch (e) { logger.error(`OTP email failed: ${e.message}`); }

    logger.info(`New user registered: ${user.email}`);
    return ok(res, 201, 'Registration successful! Check your email for the verification code.', {
      email: user.email, requiresVerification: true,
      otpExpiresIn: `${process.env.OTP_EXPIRES_MINUTES || 10} minutes`,
    });
  } catch (err) { next(err); }
};

// POST /api/auth/verify-email
const handleVerifyEmail = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() }).select(
      '+emailVerificationOTP +emailVerificationOTPExpires +emailVerificationAttempts'
    );

    if (!user)                return fail(res, 404, 'No account found with this email.');
    if (user.isEmailVerified)  return fail(res, 400, 'Email already verified. Please log in.');
    if (user.emailVerificationAttempts >= 5)
      return fail(res, 429, 'Too many failed attempts. Request a new code.');
    if (!user.emailVerificationOTPExpires || isOTPExpired(user.emailVerificationOTPExpires))
      return fail(res, 400, 'Verification code has expired. Request a new one.');

    if (user.emailVerificationOTP !== otp.toString().trim()) {
      user.emailVerificationAttempts += 1;
      await user.save();
      const left = 5 - user.emailVerificationAttempts;
      return fail(res, 400, `Invalid code. ${left > 0 ? `${left} attempt(s) remaining.` : 'No attempts left. Request a new code.'}`);
    }

    // ✅ OTP is valid
    user.isEmailVerified             = true;
    user.emailVerificationOTP        = undefined;
    user.emailVerificationOTPExpires = undefined;
    user.emailVerificationAttempts   = 0;
    user.lastLoginAt                 = new Date();
    user.loginCount                 += 1;
    user.lastLoginIP                 = req.ip;

    const accessToken  = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    user.refreshTokens = [...(user.refreshTokens || []).slice(-4), refreshToken];
    await user.save();

    setTokenCookies(res, accessToken, refreshToken);

    try { await sendWelcomeEmail({ to: user.email, name: user.firstName }); }
    catch (e) { logger.error(`Welcome email failed: ${e.message}`); }

    logger.info(`Email verified: ${user.email}`);
    return ok(res, 200, 'Email verified! Welcome to AffiliateEngine.', {
      user: user.toSafeObject(),
      tokens: { accessToken, refreshToken, expiresIn: process.env.JWT_EXPIRES_IN || '7d' },
    });
  } catch (err) { next(err); }
};

// POST /api/auth/resend-otp
const handleResendOTP = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() }).select(
      '+emailVerificationOTP +emailVerificationOTPExpires +emailVerificationAttempts'
    );

    if (!user)                return fail(res, 404, 'No account found with this email.');
    if (user.isEmailVerified)  return fail(res, 400, 'This email is already verified.');

    const otp    = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
    const expiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));

    user.emailVerificationOTP        = otp;
    user.emailVerificationOTPExpires = expiry;
    user.emailVerificationAttempts   = 0;
    await user.save();

    await sendResendOTPEmail({ to: user.email, name: user.firstName, otp });
    logger.info(`OTP resent to: ${user.email}`);

    return ok(res, 200, 'New verification code sent to your email.', {
      email: user.email,
      otpExpiresIn: `${process.env.OTP_EXPIRES_MINUTES || 10} minutes`,
    });
  } catch (err) { next(err); }
};

// POST /api/auth/login
const handleLogin = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findByEmailWithPassword(email);
    if (!user) return fail(res, 401, 'Invalid email or password.');

    if (!user.isActive || user.isBanned)
      return fail(res, 403, 'Account suspended. Contact support.');

    const valid = await user.comparePassword(password);
    if (!valid) {
      logger.warn(`Failed login: ${email} | IP: ${req.ip}`);
      return fail(res, 401, 'Invalid email or password.');
    }

    if (!user.isEmailVerified) {
      const otp    = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
      const expiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));
      await User.updateOne({ _id: user._id }, {
        emailVerificationOTP: otp,
        emailVerificationOTPExpires: expiry,
        emailVerificationAttempts: 0,
      });
      try { await sendOTPEmail({ to: user.email, name: user.firstName, otp }); }
      catch (e) { logger.error(`OTP resend on login failed: ${e.message}`); }

      return fail(res, 403, 'Email not verified. A new OTP has been sent to your email.', {
        requiresVerification: true, email: user.email,
      });
    }

    const accessToken  = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.lastLoginAt   = new Date();
    user.lastLoginIP   = req.ip;
    user.loginCount   += 1;
    user.refreshTokens = [...(user.refreshTokens || []).slice(-4), refreshToken];
    await user.save();

    setTokenCookies(res, accessToken, refreshToken);
    logger.info(`User logged in: ${user.email} | IP: ${req.ip}`);

    return ok(res, 200, 'Login successful!', {
      user: user.toSafeObject(),
      tokens: { accessToken, refreshToken, expiresIn: process.env.JWT_EXPIRES_IN || '7d' },
    });
  } catch (err) { next(err); }
};

// POST /api/auth/refresh-token
const handleRefreshToken = async (req, res, next) => {
  try {
    const token = req.body.refreshToken || req.cookies.refreshToken;
    if (!token) return fail(res, 401, 'Refresh token not provided.');

    let decoded;
    try { decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET); }
    catch { return fail(res, 401, 'Invalid or expired refresh token. Please log in again.'); }

    const user = await User.findById(decoded.id).select('+refreshTokens');
    if (!user || !(user.refreshTokens || []).includes(token))
      return fail(res, 401, 'Refresh token not recognized. Please log in again.');

    const newAccessToken  = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    user.refreshTokens = [
      ...(user.refreshTokens || []).filter((t) => t !== token).slice(-4),
      newRefreshToken,
    ];
    await user.save();

    setTokenCookies(res, newAccessToken, newRefreshToken);
    return ok(res, 200, 'Token refreshed.', {
      tokens: { accessToken: newAccessToken, refreshToken: newRefreshToken, expiresIn: process.env.JWT_EXPIRES_IN || '7d' },
    });
  } catch (err) { next(err); }
};

// POST /api/auth/logout
const handleLogout = async (req, res, next) => {
  try {
    const token = req.body.refreshToken || req.cookies.refreshToken;
    if (token) await User.findByIdAndUpdate(req.user._id, { $pull: { refreshTokens: token } });
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken', { path: '/api/auth/refresh-token' });
    logger.info(`User logged out: ${req.user.email}`);
    return ok(res, 200, 'Logged out successfully.');
  } catch (err) { next(err); }
};

// GET /api/auth/me
const handleGetMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return fail(res, 404, 'User not found.');
    return ok(res, 200, 'Profile retrieved.', { user: user.toSafeObject() });
  } catch (err) { next(err); }
};

// ─────────────────────────────────────────────────────────────
//  SECTION 12 — EXPRESS APP SETUP
// ─────────────────────────────────────────────────────────────

const app = express();

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:', 'https:'],
      scriptSrc:  ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

const allowedOrigins = [
  process.env.FRONTEND_URL,
  process.env.APP_URL,
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:4200',
].filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin)                                return cb(null, true);
    if (allowedOrigins.includes(origin))        return cb(null, true);
    if (process.env.NODE_ENV !== 'production')  return cb(null, true);
    cb(new Error(`CORS: Origin ${origin} not allowed.`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

app.use(morgan(
  process.env.NODE_ENV === 'production' ? 'combined' : 'dev',
  { stream: { write: (msg) => logger.http(msg.trim()) } }
));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use('/api/', generalLimiter);

// ─────────────────────────────────────────────────────────────
//  SECTION 13 — ROUTES
// ─────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  const states    = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  const dbStatus  = states[mongoose.connection.readyState] || 'unknown';
  const isUp      = mongoose.connection.readyState === 1;
  res.status(isUp ? 200 : 503).json({
    status:      isUp ? 'ok' : 'degraded',
    service:     'AffiliateEngine API',
    version:     '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    database:    { status: dbStatus, connected: isUp },
    uptime:      Math.floor(process.uptime()),
    memory: {
      used:  `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
      total: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
    },
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (req, res) => {
  res.json({
    name: 'AffiliateEngine API', version: '1.0.0',
    endpoints: {
      register:     'POST /api/auth/register',
      verifyEmail:  'POST /api/auth/verify-email',
      resendOTP:    'POST /api/auth/resend-otp',
      login:        'POST /api/auth/login',
      logout:       'POST /api/auth/logout',
      refreshToken: 'POST /api/auth/refresh-token',
      profile:      'GET  /api/auth/me',
      health:       'GET  /health',
    },
  });
});

app.post('/api/auth/register',      authLimiter,      registerValidation,    validateRequest, handleRegister);
app.post('/api/auth/verify-email',  authLimiter,      verifyEmailValidation, validateRequest, handleVerifyEmail);
app.post('/api/auth/resend-otp',    otpResendLimiter, resendOTPValidation,   validateRequest, handleResendOTP);
app.post('/api/auth/login',         authLimiter,      loginValidation,       validateRequest, handleLogin);
app.post('/api/auth/refresh-token',                                                           handleRefreshToken);
app.post('/api/auth/logout',        protect,                                                  handleLogout);
app.get( '/api/auth/me',            protect,          requireEmailVerified,                   handleGetMe);

app.use((req, res) => fail(res, 404, `Route not found: ${req.method} ${req.originalUrl}`));
app.use(errorHandler);

// ─────────────────────────────────────────────────────────────
//  SECTION 14 — SERVER STARTUP
// ─────────────────────────────────────────────────────────────

process.on('uncaughtException', (err) => {
  logger.error(`UNCAUGHT EXCEPTION: ${err.message}`, { stack: err.stack });
  process.exit(1);
});

const PORT = parseInt(process.env.PORT || '5000', 10);
const HOST = '0.0.0.0';

const startServer = async () => {
  try {
    await connectDB();
    const server = app.listen(PORT, HOST, () => {
      logger.info(`🚀 AffiliateEngine API → port ${PORT}`);
      logger.info(`📍 Env: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`🌐 Health: http://${HOST}:${PORT}/health`);
    });

    process.on('unhandledRejection', (reason) => {
      logger.error('UNHANDLED REJECTION', { reason });
      server.close(() => process.exit(1));
    });
    process.on('SIGTERM', () => {
      logger.info('SIGTERM → graceful shutdown...');
      server.close(() => { logger.info('Server closed.'); process.exit(0); });
    });
  } catch (err) {
    logger.error(`Startup failed: ${err.message}`);
    process.exit(1);
  }
};

startServer();
