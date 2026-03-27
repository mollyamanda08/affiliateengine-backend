const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const ApiResponse = require('../utils/apiResponse');

/**
 * @route   GET /health
 * @desc    Health check — used by Render.com and load balancers
 * @access  Public
 */
router.get('/', (req, res) => {
  const dbState = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  const dbStatus = dbState[mongoose.connection.readyState] || 'unknown';

  const health = {
    status: 'ok',
    service: 'AffiliateEngine API',
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    database: {
      status: dbStatus,
      connected: mongoose.connection.readyState === 1,
    },
    uptime: Math.floor(process.uptime()),
    memory: {
      used: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
      total: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
    },
    timestamp: new Date().toISOString(),
  };

  const statusCode = mongoose.connection.readyState === 1 ? 200 : 503;
  return res.status(statusCode).json(health);
});

module.exports = router;
