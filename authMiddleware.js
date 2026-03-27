const jwt = require('jsonwebtoken');
const User = require('../models/User');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');

/**
 * Protect routes - verifies JWT access token
 */
const protect = async (req, res, next) => {
  try {
    let token;

    // 1. Check Authorization header (Bearer token)
    if (req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // 2. Fallback: check cookie
    else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return ApiResponse.error(res, 401, 'Access denied. No token provided.');
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtError) {
      if (jwtError.name === 'TokenExpiredError') {
        return ApiResponse.error(res, 401, 'Token has expired. Please log in again.');
      }
      if (jwtError.name === 'JsonWebTokenError') {
        return ApiResponse.error(res, 401, 'Invalid token. Please log in again.');
      }
      throw jwtError;
    }

    // Find user in DB
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return ApiResponse.error(res, 401, 'User associated with this token no longer exists.');
    }

    if (!user.isActive || user.isBanned) {
      return ApiResponse.error(res, 403, 'Your account has been suspended. Please contact support.');
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error(`Auth middleware error: ${error.message}`);
    return ApiResponse.error(res, 500, 'Authentication error. Please try again.');
  }
};

/**
 * Require email verification
 */
const requireEmailVerified = (req, res, next) => {
  if (!req.user.isEmailVerified) {
    return ApiResponse.error(
      res,
      403,
      'Email verification required. Please verify your email address to access this resource.'
    );
  }
  next();
};

/**
 * Role-based access control
 * @param {...string} roles - Allowed roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return ApiResponse.error(
        res,
        403,
        `Access denied. Required roles: ${roles.join(', ')}`
      );
    }
    next();
  };
};

module.exports = { protect, requireEmailVerified, authorize };
