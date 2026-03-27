/**
 * Standardized API response helper
 */

class ApiResponse {
  /**
   * Success response
   * @param {object} res - Express response object
   * @param {number} statusCode - HTTP status code
   * @param {string} message - Response message
   * @param {object} data - Response data
   */
  static success(res, statusCode = 200, message = 'Success', data = {}) {
    return res.status(statusCode).json({
      success: true,
      message,
      data,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Error response
   * @param {object} res - Express response object
   * @param {number} statusCode - HTTP status code
   * @param {string} message - Error message
   * @param {object|null} errors - Validation errors or extra details
   */
  static error(res, statusCode = 500, message = 'Internal Server Error', errors = null) {
    const response = {
      success: false,
      message,
      timestamp: new Date().toISOString(),
    };

    if (errors) {
      response.errors = errors;
    }

    return res.status(statusCode).json(response);
  }

  /**
   * Paginated success response
   */
  static paginated(res, message = 'Success', data = [], pagination = {}) {
    return res.status(200).json({
      success: true,
      message,
      data,
      pagination,
      timestamp: new Date().toISOString(),
    });
  }
}

module.exports = ApiResponse;
