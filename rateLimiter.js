const rateLimit = require('express-rate-limit');
const ApiResponse = require('../utils/apiResponse');

/**
 * General API rate limiter
 */
const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return ApiResponse.error(
      res,
      429,
      'Too many requests from this IP. Please try again after 15 minutes.'
    );
  },
});

/**
 * Strict limiter for auth endpoints (registration, login)
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '10', 10),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
  handler: (req, res) => {
    return ApiResponse.error(
      res,
      429,
      'Too many authentication attempts. Please wait 15 minutes before trying again.'
    );
  },
});

/**
 * Very strict limiter for OTP resend (prevent OTP spam)
 */
const otpResendLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // Max 3 OTP resend attempts per 5 minutes
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return ApiResponse.error(
      res,
      429,
      'Too many OTP requests. Please wait 5 minutes before requesting a new code.'
    );
  },
});

module.exports = { generalLimiter, authLimiter, otpResendLimiter };
