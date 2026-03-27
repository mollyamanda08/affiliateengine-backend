/**
 * Environment Variable Validation
 * Validates all required env vars at startup to fail fast
 */

const REQUIRED_VARS = [
  'MONGODB_URI',
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
  'EMAIL_USER',
  'EMAIL_PASS',
];

const DEFAULTS = {
  NODE_ENV: 'development',
  PORT: '5000',
  JWT_EXPIRES_IN: '7d',
  JWT_REFRESH_EXPIRES_IN: '30d',
  OTP_EXPIRY_MINUTES: '10',
  OTP_LENGTH: '6',
  BCRYPT_SALT_ROUNDS: '12',
  RATE_LIMIT_WINDOW_MS: '900000',
  RATE_LIMIT_MAX_REQUESTS: '100',
  AUTH_RATE_LIMIT_MAX: '10',
  EMAIL_HOST: 'smtp.gmail.com',
  EMAIL_PORT: '587',
  EMAIL_SECURE: 'false',
  EMAIL_FROM_NAME: 'AffiliateEngine',
  APP_NAME: 'AffiliateEngine',
  FRONTEND_URL: 'http://localhost:3000',
};

/**
 * Validates env vars and applies defaults
 */
const validateEnv = () => {
  // Apply defaults for optional vars
  for (const [key, value] of Object.entries(DEFAULTS)) {
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }

  // Check required vars in production
  if (process.env.NODE_ENV === 'production') {
    const missing = REQUIRED_VARS.filter((key) => !process.env[key]);
    if (missing.length > 0) {
      throw new Error(
        `Missing required environment variables: ${missing.join(', ')}\n` +
        'Please check your .env file or Render.com environment settings.'
      );
    }
  }

  // Warn about missing vars in development
  if (process.env.NODE_ENV !== 'test') {
    const missing = REQUIRED_VARS.filter((key) => !process.env[key]);
    if (missing.length > 0) {
      console.warn(
        `⚠️  Warning: Missing environment variables: ${missing.join(', ')}`
      );
    }
  }
};

module.exports = { validateEnv };
