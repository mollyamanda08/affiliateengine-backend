const jwt = require('jsonwebtoken');
const User = require('../models/User');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { generateOTP, generateOTPExpiry, isOTPExpired } = require('../utils/otpGenerator');
const { sendOTPEmail, sendWelcomeEmail, sendResendOTPEmail } = require('../utils/emailService');

// ─── Token Generator Helpers ──────────────────────────────────────────────────

const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId, type: 'access' }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    issuer: 'affiliateengine',
    audience: 'affiliateengine-client',
  });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId, type: 'refresh' }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
    issuer: 'affiliateengine',
    audience: 'affiliateengine-client',
  });
};

const setTokenCookies = (res, accessToken, refreshToken) => {
  const isProduction = process.env.NODE_ENV === 'production';

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: '/api/auth/refresh-token', // Restrict to refresh endpoint
  });
};

// ─── @route   POST /api/auth/register ────────────────────────────────────────
// ─── @desc    Register new user and send OTP email
// ─── @access  Public
const register = async (req, res, next) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Check if email already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      if (existingUser.isEmailVerified) {
        return ApiResponse.error(res, 409, 'An account with this email already exists. Please log in.');
      }
      // Account exists but unverified — resend OTP
      const otp = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
      const otpExpiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));

      existingUser.emailVerificationOTP = otp;
      existingUser.emailVerificationOTPExpires = otpExpiry;
      existingUser.emailVerificationAttempts = 0;
      await existingUser.save();

      await sendOTPEmail({ to: existingUser.email, name: existingUser.firstName, otp });

      return ApiResponse.success(res, 200, 'An account with this email already exists but is unverified. A new OTP has been sent to your email.', {
        email: existingUser.email,
        requiresVerification: true,
      });
    }

    // Generate OTP
    const otp = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
    const otpExpiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));

    // Create user (password hashed via pre-save hook)
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      emailVerificationOTP: otp,
      emailVerificationOTPExpires: otpExpiry,
    });

    // Send OTP email (non-blocking — don't fail registration if email fails)
    try {
      await sendOTPEmail({ to: user.email, name: user.firstName, otp });
    } catch (emailError) {
      logger.error(`Failed to send OTP email to ${user.email}: ${emailError.message}`);
      // Continue — user can request resend
    }

    logger.info(`New user registered: ${user.email} (ID: ${user._id})`);

    return ApiResponse.success(res, 201, 'Registration successful! Please check your email for the verification code.', {
      email: user.email,
      requiresVerification: true,
      otpExpiresIn: `${process.env.OTP_EXPIRES_MINUTES || 10} minutes`,
    });
  } catch (error) {
    next(error);
  }
};

// ─── @route   POST /api/auth/verify-email ────────────────────────────────────
// ─── @desc    Verify email with OTP
// ─── @access  Public
const verifyEmail = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    // Find user and include OTP fields
    const user = await User.findOne({ email: email.toLowerCase() }).select(
      '+emailVerificationOTP +emailVerificationOTPExpires +emailVerificationAttempts'
    );

    if (!user) {
      return ApiResponse.error(res, 404, 'No account found with this email address.');
    }

    if (user.isEmailVerified) {
      return ApiResponse.error(res, 400, 'This email address is already verified. Please log in.');
    }

    // Check attempts (max 5)
    if (user.emailVerificationAttempts >= 5) {
      return ApiResponse.error(
        res,
        429,
        'Too many failed OTP attempts. Please request a new verification code.'
      );
    }

    // Check OTP expiry
    if (!user.emailVerificationOTPExpires || isOTPExpired(user.emailVerificationOTPExpires)) {
      return ApiResponse.error(
        res,
        400,
        'Your verification code has expired. Please request a new one.'
      );
    }

    // Validate OTP
    if (user.emailVerificationOTP !== otp.toString().trim()) {
      user.emailVerificationAttempts += 1;
      await user.save();

      const attemptsLeft = 5 - user.emailVerificationAttempts;
      return ApiResponse.error(
        res,
        400,
        `Invalid verification code. ${attemptsLeft > 0 ? `${attemptsLeft} attempt(s) remaining.` : 'No attempts remaining. Please request a new code.'}`
      );
    }

    // ✅ OTP valid — mark email as verified
    user.isEmailVerified = true;
    user.emailVerificationOTP = undefined;
    user.emailVerificationOTPExpires = undefined;
    user.emailVerificationAttempts = 0;
    user.lastLoginAt = new Date();
    user.loginCount += 1;
    user.lastLoginIP = req.ip;
    await user.save();

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Store refresh token hash
    user.refreshTokens = [...(user.refreshTokens || []).slice(-4), refreshToken];
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    // Send welcome email
    try {
      await sendWelcomeEmail({ to: user.email, name: user.firstName });
    } catch (emailError) {
      logger.error(`Welcome email failed: ${emailError.message}`);
    }

    logger.info(`Email verified for user: ${user.email}`);

    return ApiResponse.success(res, 200, 'Email verified successfully! Welcome to AffiliateEngine.', {
      user: user.toSafeObject(),
      tokens: {
        accessToken,
        refreshToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '7d',
      },
    });
  } catch (error) {
    next(error);
  }
};

// ─── @route   POST /api/auth/resend-otp ──────────────────────────────────────
// ─── @desc    Resend OTP verification email
// ─── @access  Public
const resendOTP = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() }).select(
      '+emailVerificationOTP +emailVerificationOTPExpires +emailVerificationAttempts'
    );

    if (!user) {
      return ApiResponse.error(res, 404, 'No account found with this email address.');
    }

    if (user.isEmailVerified) {
      return ApiResponse.error(res, 400, 'This email is already verified.');
    }

    // Generate new OTP
    const otp = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
    const otpExpiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));

    user.emailVerificationOTP = otp;
    user.emailVerificationOTPExpires = otpExpiry;
    user.emailVerificationAttempts = 0; // Reset attempts
    await user.save();

    await sendResendOTPEmail({ to: user.email, name: user.firstName, otp });

    logger.info(`OTP resent to: ${user.email}`);

    return ApiResponse.success(res, 200, 'A new verification code has been sent to your email.', {
      email: user.email,
      otpExpiresIn: `${process.env.OTP_EXPIRES_MINUTES || 10} minutes`,
    });
  } catch (error) {
    next(error);
  }
};

// ─── @route   POST /api/auth/login ───────────────────────────────────────────
// ─── @desc    Login user and return JWT
// ─── @access  Public
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Find user with password
    const user = await User.findByEmailWithPassword(email);

    if (!user) {
      return ApiResponse.error(res, 401, 'Invalid email or password.');
    }

    // Check account status
    if (!user.isActive || user.isBanned) {
      return ApiResponse.error(res, 403, 'Your account has been suspended. Please contact support.');
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.warn(`Failed login attempt for: ${email} | IP: ${req.ip}`);
      return ApiResponse.error(res, 401, 'Invalid email or password.');
    }

    // Check email verification
    if (!user.isEmailVerified) {
      // Optionally re-send OTP
      const otp = generateOTP(parseInt(process.env.OTP_LENGTH || '6', 10));
      const otpExpiry = generateOTPExpiry(parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10));

      await User.updateOne(
        { _id: user._id },
        {
          emailVerificationOTP: otp,
          emailVerificationOTPExpires: otpExpiry,
          emailVerificationAttempts: 0,
        }
      );

      try {
        await sendOTPEmail({ to: user.email, name: user.firstName, otp });
      } catch (emailErr) {
        logger.error(`Failed resend OTP on login: ${emailErr.message}`);
      }

      return ApiResponse.error(res, 403, 'Email not verified. A new verification code has been sent to your email.', {
        requiresVerification: true,
        email: user.email,
      });
    }

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Update login info
    user.lastLoginAt = new Date();
    user.lastLoginIP = req.ip;
    user.loginCount += 1;

    // Store refresh token (keep last 5)
    const existingTokens = user.refreshTokens || [];
    user.refreshTokens = [...existingTokens.slice(-4), refreshToken];
    await user.save();

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    logger.info(`User logged in: ${user.email} | IP: ${req.ip}`);

    return ApiResponse.success(res, 200, 'Login successful!', {
      user: user.toSafeObject(),
      tokens: {
        accessToken,
        refreshToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '7d',
      },
    });
  } catch (error) {
    next(error);
  }
};

// ─── @route   POST /api/auth/refresh-token ───────────────────────────────────
// ─── @desc    Refresh access token using refresh token
// ─── @access  Public
const refreshToken = async (req, res, next) => {
  try {
    const token = req.body.refreshToken || req.cookies.refreshToken;

    if (!token) {
      return ApiResponse.error(res, 401, 'Refresh token not provided.');
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch {
      return ApiResponse.error(res, 401, 'Invalid or expired refresh token. Please log in again.');
    }

    const user = await User.findById(decoded.id).select('+refreshTokens');

    if (!user || !(user.refreshTokens || []).includes(token)) {
      return ApiResponse.error(res, 401, 'Refresh token not recognized. Please log in again.');
    }

    // Rotate tokens (remove old, add new)
    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    user.refreshTokens = [
      ...(user.refreshTokens || []).filter((t) => t !== token).slice(-4),
      newRefreshToken,
    ];
    await user.save();

    setTokenCookies(res, newAccessToken, newRefreshToken);

    return ApiResponse.success(res, 200, 'Token refreshed successfully.', {
      tokens: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '7d',
      },
    });
  } catch (error) {
    next(error);
  }
};

// ─── @route   POST /api/auth/logout ──────────────────────────────────────────
// ─── @desc    Logout user (invalidate refresh token)
// ─── @access  Private
const logout = async (req, res, next) => {
  try {
    const token = req.body.refreshToken || req.cookies.refreshToken;
    const userId = req.user._id;

    if (token) {
      await User.findByIdAndUpdate(userId, {
        $pull: { refreshTokens: token },
      });
    }

    // Clear cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken', { path: '/api/auth/refresh-token' });

    logger.info(`User logged out: ${req.user.email}`);

    return ApiResponse.success(res, 200, 'Logged out successfully.');
  } catch (error) {
    next(error);
  }
};

// ─── @route   GET /api/auth/me ───────────────────────────────────────────────
// ─── @desc    Get current authenticated user profile
// ─── @access  Private
const getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return ApiResponse.error(res, 404, 'User not found.');
    }

    return ApiResponse.success(res, 200, 'Profile retrieved successfully.', {
      user: user.toSafeObject(),
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  verifyEmail,
  resendOTP,
  login,
  refreshToken,
  logout,
  getMe,
};
