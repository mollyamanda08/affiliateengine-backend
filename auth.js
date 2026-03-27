/**
 * Authentication Middleware
 * Protects routes by verifying JWT tokens
 */

const { verifyAccessToken } = require('../services/jwtService');
const User = require('../models/User');
const { sendError } = require('../utils/apiResponse');
const logger = require('../utils/logger');

/**
 * Protect middleware - verifies JWT access token
 * Attaches user to req.user
 */
const protect = async (req, res, next) => {
  try {
    // 1. Extract token from Authorization header or cookie
    let token = null;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return sendError(res, 401, 'Authentication required. Please log in.');
    }

    // 2. Verify token
    const decoded = verifyAccessToken(token);
    if (!decoded) {
      return sendError(res, 401, 'Invalid or expired token. Please log in again.');
    }

    // 3. Find user and check if still active
    const user = await User.findById(decoded.sub).select('+passwordChangedAt');
    if (!user) {
      return sendError(res, 401, 'User no longer exists.');
    }

    if (!user.isActive || user.isBanned) {
      return sendError(res, 403, 'Your account has been suspended. Please contact support.');
    }

    // 4. Check if password was changed after token was issued
    if (user.passwordChangedAfter(decoded.iat)) {
      return sendError(res, 401, 'Password recently changed. Please log in again.');
    }

    // 5. Attach user to request
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    logger.error(`Auth middleware error: ${error.message}`);
    return sendError(res, 500, 'Authentication error. Please try again.');
  }
};

/**
 * requireVerified - Ensures email is verified before allowing access
 */
const requireVerified = (req, res, next) => {
  if (!req.user) {
    return sendError(res, 401, 'Authentication required.');
  }
  if (!req.user.isEmailVerified) {
    return sendError(
      res,
      403,
      'Email verification required. Please verify your email address to continue.'
    );
  }
  next();
};

/**
 * Role-based access control (RBAC)
 * @param {...string} roles - Allowed roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return sendError(res, 401, 'Authentication required.');
    }
    if (!roles.includes(req.user.role)) {
      return sendError(
        res,
        403,
        `Access denied. Required role(s): ${roles.join(', ')}.`
      );
    }
    next();
  };
};

/**
 * Optional auth - attaches user if token present, continues without if not
 */
const optionalAuth = async (req, res, next) => {
  try {
    let token = null;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (token) {
      const decoded = verifyAccessToken(token);
      if (decoded) {
        const user = await User.findById(decoded.sub);
        if (user && user.isActive) {
          req.user = user;
        }
      }
    }
    next();
  } catch {
    next(); // Always continue even on error
  }
};

module.exports = { protect, requireVerified, authorize, optionalAuth };
