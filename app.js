'use strict';
require('dotenv').config();

const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app  = express();
const PORT = process.env.PORT || 5000;
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'], credentials: false }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));

const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });
const authLimiter   = rateLimit({ windowMs: 15*60*1000, max: 20 });
app.use(globalLimiter);

const MONGO_URI = process.env.MONGODB_URI || process.env.MONGO_URI;
console.log('MongoDB URI exists:', !!MONGO_URI);

if (!MONGO_URI) {
  console.error('MONGODB_URI is not set!');
} else {
  mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 })
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ MongoDB Error:', err.message));
}

const userSchema = new mongoose.Schema({
  name:       { type: String, required: true, trim: true },
  email:      { type: String, required: true, unique: true, lowercase: true },
  password:   { type: String, required: true, select: false },
  isVerified: { type: Boolean, default: false },
  role:       { type: String, enum: ['user','admin'], default: 'user' },
  lastLogin:  { type: Date, default: null }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
userSchema.methods.comparePassword = function(p) { return bcrypt.compare(p, this.password); };
userSchema.methods.toSafeObject = function() {
  return { id: this._id, name: this.name, email: this.email, isVerified: this.isVerified, role: this.role, createdAt: this.createdAt, lastLogin: this.lastLogin };
};

const User = mongoose.models.User || mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
  email:     { type: String, required: true, lowercase: true },
  code:      { type: String, required: true },
  type:      { type: String, default: 'email_verification' },
  expiresAt: { type: Date, required: true },
  used:      { type: Boolean, default: false }
}, { timestamps: true });
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OTP = mongoose.models.OTP || mongoose.model('OTP', otpSchema);

function createTransporter() {
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { 
      user: process.env.EMAIL_USER, 
      pass: process.env.EMAIL_PASS 
    }
  });
}

async function sendVerificationEmail(to, code) {
  const transporter = createTransporter();
  const html = `<div style="font-family:sans-serif;max-width:500px;margin:auto;padding:30px;border:1px solid #e2e8f0;border-radius:12px;"><h2 style="color:#3b82f6;">AffiliateEngine — Email Verification</h2><p>Your verification code is:</p><div style="font-size:36px;font-weight:bold;letter-spacing:12px;text-align:center;padding:20px;background:#f1f5f9;border-radius:8px;margin:20px 0;">${code}</div><p style="color:#64748b;">This code expires in <strong>10 minutes</strong>.</p></div>`;
  try {
    const info = await transporter.sendMail({ from: `"AffiliateEngine" <${process.env.EMAIL_USER}>`, to, subject: 'Verify your email — AffiliateEngine', html });
    console.log('✅ Email sent:', info.messageId);
    return { success: true };
  } catch (err) {
    console.error('❌ Email error:', err.message);
    return { success: false, error: err.message };
  }
}

function generateOTP() { return Math.floor(100000 + Math.random() * 900000).toString(); }

async function createOTP(email, type = 'email_verification') {
  await OTP.deleteMany({ email: email.toLowerCase(), type, used: false });
  const code = generateOTP();
  await OTP.create({ email: email.toLowerCase(), code, type, expiresAt: new Date(Date.now() + 10*60*1000) });
  return code;
}

async function verifyOTP(email, code, type = 'email_verification') {
  const otp = await OTP.findOne({ email: email.toLowerCase(), code, type, used: false, expiresAt: { $gt: new Date() } });
  if (!otp) return false;
  otp.used = true;
  await otp.save();
  return true;
}

function generateToken(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET || 'fallback_secret');
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array()[0].msg });
  next();
}

app.get('/health', (req, res) => {
  res.json({ success: true, status: 'healthy', timestamp: new Date().toISOString(), mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

app.get('/api', (req, res) => {
  res.json({ success: true, message: 'AffiliateEngine Auth API v1.0.0' });
});

app.post('/api/auth/register', authLimiter, [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2-100 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], validate, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) {
      if (!exists.isVerified) {
        const code = await createOTP(email, 'email_verification');
        await sendVerificationEmail(email, code);
        return res.status(200).json({ success: true, message: 'Account exists but unverified. New code sent.', requiresVerification: true, email });
      }
      return res.status(409).json({ success: false, message: 'Email already registered. Please login.' });
    }
    const user = await User.create({ name, email, password });
    const code = await createOTP(email, 'email_verification');
    const emailResult = await sendVerificationEmail(email, code);
    res.status(201).json({ success: true, message: 'Registration successful! Check your email for the verification code.', email, userId: user._id, emailSent: emailResult.success });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, message: 'Server error.', error: process.env.NODE_ENV !== 'production' ? err.message : undefined });
  }
});

app.post('/api/auth/verify-email', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('code').isLength({ min: 6, max: 6 }).isNumeric().withMessage('6-digit code required')
], validate, async (req, res) => {
  try {
    const { email, code } = req.body;
    const valid = await verifyOTP(email, code, 'email_verification');
    if (!valid) return res.status(400).json({ success: false, message: 'Invalid or expired code.' });
    const user = await User.findOneAndUpdate({ email: email.toLowerCase() }, { isVerified: true, lastLogin: new Date() }, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    const token = generateToken(user._id);
    res.json({ success: true, message: 'Email verified! Welcome to AffiliateEngine.', token, user: user.toSafeObject() });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/auth/resend-code', authLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required')
], validate, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ success: false, message: 'No account found.' });
    if (user.isVerified) return res.status(400).json({ success: false, message: 'Email already verified.' });
    const code = await createOTP(email, 'email_verification');
    const emailResult = await sendVerificationEmail(email, code);
    if (!emailResult.success) return res.status(500).json({ success: false, message: 'Could not send email.' });
    res.json({ success: true, message: 'Verification code resent!' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/auth/login', authLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password required')
], validate, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    const match = await user.comparePassword(password);
    if (!match) return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    if (!user.isVerified) {
      const code = await createOTP(email, 'email_verification');
      await sendVerificationEmail(email, code);
      return res.status(403).json({ success: false, message: 'Email not verified. New code sent.', requiresVerification: true, email });
    }
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });
    const token = generateToken(user._id);
    res.json({ success: true, message: 'Login successful!', token, user: user.toSafeObject() });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, user: user.toSafeObject() });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
  res.json({ success: true, message: 'Logged out successfully.' });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route ${req.method} ${req.path} not found.` });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Health: http://localhost:${PORT}/health`);
  console.log(`📡 API: http://localhost:${PORT}/api`);
});

module.exports = app;
