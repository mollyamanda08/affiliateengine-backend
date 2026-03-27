const logger = require('../utils/logger');
const ApiResponse = require('../utils/apiResponse');

/**
 * 404 Not Found handler
 */
const notFound = (req, res, next) => {
  const error = new Error(`Route not found: ${req.method} ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
};

/**
 * Global error handler middleware
 */
const errorHandler = (err, req, res, next) => {
  let statusCode = err.statusCode || err.status || 500;
  let message = err.message || 'Internal Server Error';

  // ─── Mongoose Validation Error ──────────────────────────────────
  if (err.name === 'ValidationError') {
    statusCode = 400;
    const errors = Object.values(err.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    message = 'Validation failed';
    logger.warn(`Validation error: ${JSON.stringify(errors)}`);
    return ApiResponse.error(res, statusCode, message, errors);
  }

  // ─── Mongoose Duplicate Key ──────────────────────────────────────
  if (err.code === 11000) {
    statusCode = 409;
    const field = Object.keys(err.keyValue || {})[0];
    message = `An account with this ${field || 'value'} already exists.`;
    logger.warn(`Duplicate key error: ${JSON.stringify(err.keyValue)}`);
    return ApiResponse.error(res, statusCode, message);
  }

  // ─── Mongoose CastError (invalid ObjectId) ──────────────────────
  if (err.name === 'CastError') {
    statusCode = 400;
    message = `Invalid ${err.path}: ${err.value}`;
  }

  // ─── JWT Errors ─────────────────────────────────────────────────
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token. Please log in again.';
  }
  if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired. Please log in again.';
  }

  // ─── Log server errors ──────────────────────────────────────────
  if (statusCode >= 500) {
    logger.error(`[${statusCode}] ${message}`, {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      stack: err.stack,
    });
  } else {
    logger.warn(`[${statusCode}] ${message} | ${req.method} ${req.originalUrl}`);
  }

  // Don't leak stack traces in production
  const responseData =
    process.env.NODE_ENV !== 'production' ? { stack: err.stack } : null;

  return ApiResponse.error(res, statusCode, message, responseData);
};

module.exports = { notFound, errorHandler };
