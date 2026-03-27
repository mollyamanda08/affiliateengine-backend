/**
 * Email HTML templates for AffiliateEngine
 */

const baseLayout = (content) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AffiliateEngine</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; }
    .wrapper { max-width: 600px; margin: 40px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
    .header { background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); padding: 36px 40px; text-align: center; }
    .header h1 { color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
    .header p { color: rgba(255,255,255,0.85); font-size: 14px; margin-top: 6px; }
    .body { padding: 40px 40px 30px; }
    .body h2 { font-size: 22px; color: #1e1e2e; margin-bottom: 12px; }
    .body p { font-size: 15px; color: #555; line-height: 1.7; margin-bottom: 16px; }
    .otp-box { background: linear-gradient(135deg, #f0f0ff 0%, #f8f0ff 100%); border: 2px dashed #a78bfa; border-radius: 10px; padding: 24px; text-align: center; margin: 24px 0; }
    .otp-code { font-size: 42px; font-weight: 800; letter-spacing: 12px; color: #6366f1; font-family: 'Courier New', monospace; }
    .otp-meta { font-size: 13px; color: #888; margin-top: 10px; }
    .alert-box { background: #fff8e1; border-left: 4px solid #ffc107; border-radius: 6px; padding: 14px 18px; margin: 20px 0; font-size: 13px; color: #7a6200; }
    .btn { display: inline-block; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-size: 15px; font-weight: 600; margin: 10px 0; }
    .divider { border: none; border-top: 1px solid #eeeeee; margin: 28px 0; }
    .footer { background: #f9fafc; padding: 24px 40px; text-align: center; font-size: 12px; color: #aaa; }
    .footer a { color: #6366f1; text-decoration: none; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      <h1>🚀 AffiliateEngine</h1>
      <p>Grow smarter. Earn faster.</p>
    </div>
    <div class="body">
      ${content}
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} AffiliateEngine. All rights reserved.</p>
      <p style="margin-top: 8px;">
        If you didn't request this email, please <a href="#">contact support</a>.
      </p>
    </div>
  </div>
</body>
</html>
`;

/**
 * OTP Verification email template
 */
const otpVerificationTemplate = ({ name, otp, expiresInMinutes = 10 }) => {
  const content = `
    <h2>Verify your email address 📬</h2>
    <p>Hi <strong>${name}</strong>,</p>
    <p>Thanks for registering with AffiliateEngine! To complete your account setup, please verify your email address using the one-time password (OTP) below:</p>

    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-meta">⏰ This code expires in <strong>${expiresInMinutes} minutes</strong></div>
    </div>

    <div class="alert-box">
      🔒 <strong>Security Notice:</strong> Never share this code with anyone. AffiliateEngine staff will never ask for your OTP.
    </div>

    <p>If you didn't create an account, you can safely ignore this email.</p>
  `;
  return baseLayout(content);
};

/**
 * Welcome email template (after successful verification)
 */
const welcomeTemplate = ({ name, appUrl }) => {
  const content = `
    <h2>Welcome to AffiliateEngine! 🎉</h2>
    <p>Hi <strong>${name}</strong>,</p>
    <p>Your email has been successfully verified. You're now a member of AffiliateEngine — the smarter way to manage and grow your affiliate business.</p>

    <p style="text-align: center; margin: 28px 0;">
      <a href="${appUrl}" class="btn">Get Started Now →</a>
    </p>

    <hr class="divider" />

    <p><strong>Here's what you can do next:</strong></p>
    <p>✅ Complete your profile<br/>
       📊 Set up your first campaign<br/>
       💰 Connect your payout method<br/>
       🔗 Start sharing affiliate links</p>

    <p>Have questions? Reply to this email or visit our help center.</p>
  `;
  return baseLayout(content);
};

/**
 * Password reset / OTP resend email template
 */
const resendOtpTemplate = ({ name, otp, expiresInMinutes = 10 }) => {
  const content = `
    <h2>New Verification Code 🔄</h2>
    <p>Hi <strong>${name}</strong>,</p>
    <p>You requested a new OTP for your AffiliateEngine account. Here is your new code:</p>

    <div class="otp-box">
      <div class="otp-code">${otp}</div>
      <div class="otp-meta">⏰ This code expires in <strong>${expiresInMinutes} minutes</strong></div>
    </div>

    <div class="alert-box">
      🔒 <strong>Security Notice:</strong> Your previous code has been invalidated. Never share this code with anyone.
    </div>

    <p>If you didn't request a new code, please secure your account immediately by contacting support.</p>
  `;
  return baseLayout(content);
};

module.exports = {
  otpVerificationTemplate,
  welcomeTemplate,
  resendOtpTemplate,
};
