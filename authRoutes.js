const express = require('express');
const router = express.Router();
const { body } = require('express-validator');

const {
  register,
  verifyEmail,
  resendOTP,
  login,
  refreshToken,
  logout,
  getMe,
} = require('../controllers/authController');

const { protect } = require('../middleware/authMiddleware');
const validateRequest = require('../middleware/validateRequest');
const { authLimiter, otpResendLimiter } = require('../middleware/rateLimiter');

// ─── Validation Rules ─────────────────────────────────────────────────────────

const registerValidation = [
  body('firstName')
    .trim()
    .notEmpty().withMessage('First name is required.')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters.'),

  body('lastName')
    .trim()
    .notEmpty().withMessage('Last name is required.')
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters.'),

  body('email')
    .trim()
    .notEmpty().withMessage('Email address is required.')
    .isEmail().withMessage('Please provide a valid email address.')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required.')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number.'),
];

const verifyEmailValidation = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email address is required.')
    .isEmail().withMessage('Please provide a valid email address.')
    .normalizeEmail(),

  body('otp')
    .trim()
    .notEmpty().withMessage('OTP code is required.')
    .isLength({ min: 6, max: 6 }).withMessage('OTP must be exactly 6 digits.')
    .isNumeric().withMessage('OTP must contain only numbers.'),
];

const resendOTPValidation = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email address is required.')
    .isEmail().withMessage('Please provide a valid email address.')
    .normalizeEmail(),
];

const loginValidation = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email address is required.')
    .isEmail().withMessage('Please provide a valid email address.')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required.'),
];

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 * @body    { firstName, lastName, email, password }
 */
router.post(
  '/register',
  authLimiter,
  registerValidation,
  validateRequest,
  register
);

/**
 * @route   POST /api/auth/verify-email
 * @desc    Verify email with 6-digit OTP
 * @access  Public
 * @body    { email, otp }
 */
router.post(
  '/verify-email',
  authLimiter,
  verifyEmailValidation,
  validateRequest,
  verifyEmail
);

/**
 * @route   POST /api/auth/resend-otp
 * @desc    Resend OTP to email
 * @access  Public
 * @body    { email }
 */
router.post(
  '/resend-otp',
  otpResendLimiter,
  resendOTPValidation,
  validateRequest,
  resendOTP
);

/**
 * @route   POST /api/auth/login
 * @desc    Login with email and password
 * @access  Public
 * @body    { email, password }
 */
router.post(
  '/login',
  authLimiter,
  loginValidation,
  validateRequest,
  login
);

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refresh JWT access token
 * @access  Public
 * @body    { refreshToken } or Cookie: refreshToken
 */
router.post('/refresh-token', refreshToken);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (invalidate refresh token)
 * @access  Private
 */
router.post('/logout', protect, logout);

/**
 * @route   GET /api/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me', protect, getMe);

module.exports = router;
