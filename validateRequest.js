const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');

/**
 * Middleware to handle express-validator results
 * Place after validation chains in routes
 */
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map((err) => ({
      field: err.path,
      message: err.msg,
      value: err.value,
    }));

    return ApiResponse.error(res, 422, 'Validation failed. Please check your input.', formattedErrors);
  }

  next();
};

module.exports = validateRequest;
