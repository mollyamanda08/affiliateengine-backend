/**
 * API Routes - Central Router
 * Mounts all route modules under /api prefix
 */

const express = require('express');
const authRoutes = require('./authRoutes');

const router = express.Router();

// ---- Mount Routes ----
router.use('/auth', authRoutes);

// ---- API Info ----
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'AffiliateEngine API',
    version: '1.0.0',
    documentation: '/api/docs',
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        verifyEmail: 'POST /api/auth/verify-email',
        resendOTP: 'POST /api/auth/resend-otp',
        login: 'POST /api/auth/login',
        logout: 'POST /api/auth/logout',
        logoutAll: 'POST /api/auth/logout-all',
        refreshToken: 'POST /api/auth/refresh-token',
        forgotPassword: 'POST /api/auth/forgot-password',
        resetPassword: 'POST /api/auth/reset-password',
        changePassword: 'POST /api/auth/change-password',
        me: 'GET /api/auth/me',
      },
    },
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
