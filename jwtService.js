/**
 * JWT Service
 * Handles token generation, verification, and refresh logic
 */

const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '30d';

/**
 * Generate an access JWT token
 * @param {Object} payload - Data to encode in token
 * @returns {string} Signed JWT token
 */
const generateAccessToken = (payload) => {
  if (!JWT_SECRET) throw new Error('JWT_SECRET is not configured');
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: 'affiliateengine',
    audience: 'affiliateengine-client',
  });
};

/**
 * Generate a refresh JWT token
 * @param {Object} payload - Data to encode
 * @returns {string} Signed refresh JWT token
 */
const generateRefreshToken = (payload) => {
  if (!JWT_REFRESH_SECRET) throw new Error('JWT_REFRESH_SECRET is not configured');
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: JWT_REFRESH_EXPIRES_IN,
    issuer: 'affiliateengine',
    audience: 'affiliateengine-client',
  });
};

/**
 * Verify an access token
 * @param {string} token - JWT to verify
 * @returns {Object|null} Decoded payload or null
 */
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: 'affiliateengine',
      audience: 'affiliateengine-client',
    });
  } catch (error) {
    logger.debug(`Access token verification failed: ${error.message}`);
    return null;
  }
};

/**
 * Verify a refresh token
 * @param {string} token - Refresh JWT to verify
 * @returns {Object|null} Decoded payload or null
 */
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET, {
      issuer: 'affiliateengine',
      audience: 'affiliateengine-client',
    });
  } catch (error) {
    logger.debug(`Refresh token verification failed: ${error.message}`);
    return null;
  }
};

/**
 * Generate token pair (access + refresh)
 * @param {Object} user - User document
 * @returns {{ accessToken, refreshToken, expiresIn }}
 */
const generateTokenPair = (user) => {
  const payload = {
    sub: user._id.toString(),
    email: user.email,
    role: user.role,
  };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken({ sub: user._id.toString() });

  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: JWT_EXPIRES_IN,
  };
};

/**
 * Decode token without verification (for debugging/logging)
 * @param {string} token
 * @returns {Object|null}
 */
const decodeToken = (token) => {
  try {
    return jwt.decode(token);
  } catch {
    return null;
  }
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  generateTokenPair,
  decodeToken,
};
