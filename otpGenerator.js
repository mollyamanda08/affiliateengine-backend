const crypto = require('crypto');

/**
 * Generates a cryptographically secure numeric OTP
 * @param {number} length - Length of OTP (default: 6)
 * @returns {string} - Zero-padded OTP string
 */
const generateOTP = (length = 6) => {
  const max = Math.pow(10, length);
  const min = Math.pow(10, length - 1);

  // Use crypto.randomInt for cryptographic security
  const otp = crypto.randomInt(min, max);
  return otp.toString().padStart(length, '0');
};

/**
 * Generates OTP expiry date
 * @param {number} minutes - Minutes until expiry (default: 10)
 * @returns {Date} - Expiry date
 */
const generateOTPExpiry = (minutes = 10) => {
  const expiresAt = new Date();
  expiresAt.setMinutes(expiresAt.getMinutes() + minutes);
  return expiresAt;
};

/**
 * Checks if OTP has expired
 * @param {Date} expiresAt - Expiry date from database
 * @returns {boolean}
 */
const isOTPExpired = (expiresAt) => {
  return new Date() > new Date(expiresAt);
};

module.exports = { generateOTP, generateOTPExpiry, isOTPExpired };
