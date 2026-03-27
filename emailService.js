const nodemailer = require('nodemailer');
const logger = require('./logger');
const {
  otpVerificationTemplate,
  welcomeTemplate,
  resendOtpTemplate,
} = require('./emailTemplates');

/**
 * Creates and caches the Nodemailer transporter
 */
let transporter = null;

const createTransporter = () => {
  if (transporter) return transporter;

  transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // TLS
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD, // Use Gmail App Password (not account password)
    },
    pool: true,          // Use connection pool for multiple emails
    maxConnections: 5,
    maxMessages: 100,
    tls: {
      rejectUnauthorized: true,
    },
  });

  // Verify connection on startup
  transporter.verify((error) => {
    if (error) {
      logger.error(`Email service error: ${error.message}`);
    } else {
      logger.info('✅ Email service (Gmail SMTP) is ready.');
    }
  });

  return transporter;
};

/**
 * Core send email function
 * @param {object} options
 */
const sendEmail = async ({ to, subject, html, text }) => {
  try {
    const transport = createTransporter();

    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || 'AffiliateEngine'}" <${process.env.GMAIL_USER}>`,
      to,
      subject,
      html,
      text: text || 'Please view this email in an HTML-capable client.',
    };

    const info = await transport.sendMail(mailOptions);
    logger.info(`📧 Email sent to ${to} | MessageId: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    logger.error(`Failed to send email to ${to}: ${error.message}`);
    throw new Error(`Email delivery failed: ${error.message}`);
  }
};

/**
 * Send OTP Verification Email
 */
const sendOTPEmail = async ({ to, name, otp }) => {
  const expiresInMinutes = parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10);
  return sendEmail({
    to,
    subject: `${otp} is your AffiliateEngine verification code`,
    html: otpVerificationTemplate({ name, otp, expiresInMinutes }),
    text: `Your AffiliateEngine verification code is: ${otp}. It expires in ${expiresInMinutes} minutes.`,
  });
};

/**
 * Send Welcome Email (after verified)
 */
const sendWelcomeEmail = async ({ to, name }) => {
  const appUrl = process.env.APP_URL || 'https://affiliateengine.com';
  return sendEmail({
    to,
    subject: `Welcome to AffiliateEngine, ${name}! 🎉`,
    html: welcomeTemplate({ name, appUrl }),
    text: `Welcome to AffiliateEngine, ${name}! Your account is now verified. Visit ${appUrl} to get started.`,
  });
};

/**
 * Send Resend OTP Email
 */
const sendResendOTPEmail = async ({ to, name, otp }) => {
  const expiresInMinutes = parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10);
  return sendEmail({
    to,
    subject: `Your new AffiliateEngine verification code`,
    html: resendOtpTemplate({ name, otp, expiresInMinutes }),
    text: `Your new AffiliateEngine verification code is: ${otp}. It expires in ${expiresInMinutes} minutes.`,
  });
};

module.exports = {
  sendOTPEmail,
  sendWelcomeEmail,
  sendResendOTPEmail,
};
