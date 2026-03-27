# 🚀 AffiliateEngine — Backend API

Production-ready Node.js + Express backend for the AffiliateEngine platform.

---

## ✨ Features

- ✅ User Registration (firstName, lastName, email, password)
- ✅ Email Verification with 6-digit OTP (10-minute expiry)
- ✅ Secure Login with JWT Access Token + Refresh Token rotation
- ✅ MongoDB Atlas integration (Mongoose ODM)
- ✅ Nodemailer via Gmail SMTP with beautiful HTML email templates
- ✅ Rate limiting (general + auth + OTP-specific)
- ✅ Helmet.js security headers
- ✅ CORS with configurable origins
- ✅ MongoDB sanitization (prevent injection)
- ✅ Winston logger (file + console)
- ✅ Global error handler with structured responses
- ✅ Health check endpoint for Render.com
- ✅ Graceful shutdown handling

---

## 📁 Project Structure

```
affiliateengine-backend/
├── src/
│   ├── config/
│   │   └── database.js          # MongoDB Atlas connection
│   ├── controllers/
│   │   └── authController.js    # Register, verify OTP, login, logout, me
│   ├── middleware/
│   │   ├── authMiddleware.js    # JWT protect, requireEmailVerified, authorize
│   │   ├── errorHandler.js      # Global error + 404 handler
│   │   ├── rateLimiter.js       # express-rate-limit configurations
│   │   └── validateRequest.js   # express-validator error handler
│   ├── models/
│   │   └── User.js              # Mongoose User schema
│   ├── routes/
│   │   ├── authRoutes.js        # Auth endpoints with validation chains
│   │   └── healthRoutes.js      # /health endpoint for Render.com
│   ├── utils/
│   │   ├── apiResponse.js       # Standardized JSON response helper
│   │   ├── emailService.js      # Nodemailer transporter & send functions
│   │   ├── emailTemplates.js    # HTML email templates (OTP, welcome)
│   │   ├── logger.js            # Winston logger
│   │   └── otpGenerator.js      # Crypto-secure OTP generation
│   ├── app.js                   # Express app setup, middleware, routes
│   └── server.js                # Entry point — starts server & DB
├── logs/                        # Auto-created log files
├── .env.example                 # Environment variable template
├── .gitignore
├── package.json
├── render.yaml                  # One-click Render.com deploy config
└── README.md
```

---

## 🔌 API Endpoints

### Authentication

| Method | Endpoint                     | Auth     | Description                        |
|--------|------------------------------|----------|------------------------------------|
| POST   | `/api/auth/register`         | Public   | Register new user                  |
| POST   | `/api/auth/verify-email`     | Public   | Verify email with 6-digit OTP      |
| POST   | `/api/auth/resend-otp`       | Public   | Resend OTP to email                |
| POST   | `/api/auth/login`            | Public   | Login and receive JWT tokens       |
| POST   | `/api/auth/refresh-token`    | Public   | Refresh access token               |
| POST   | `/api/auth/logout`           | Private  | Logout and invalidate refresh token|
| GET    | `/api/auth/me`               | Private  | Get current user profile           |

### System

| Method | Endpoint    | Auth   | Description           |
|--------|-------------|--------|-----------------------|
| GET    | `/health`   | Public | Server health status  |
| GET    | `/`         | Public | API info & endpoints  |

---

## 📋 Request/Response Examples

### Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "password": "MyPass123"
}
```

**Response 201:**
```json
{
  "success": true,
  "message": "Registration successful! Please check your email for the verification code.",
  "data": {
    "email": "john@example.com",
    "requiresVerification": true,
    "otpExpiresIn": "10 minutes"
  }
}
```

---

### Verify Email
```http
POST /api/auth/verify-email
Content-Type: application/json

{
  "email": "john@example.com",
  "otp": "482951"
}
```

**Response 200:**
```json
{
  "success": true,
  "message": "Email verified successfully! Welcome to AffiliateEngine.",
  "data": {
    "user": { "id": "...", "firstName": "John", ... },
    "tokens": {
      "accessToken": "eyJhbGci...",
      "refreshToken": "eyJhbGci...",
      "expiresIn": "7d"
    }
  }
}
```

---

### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "MyPass123"
}
```

---

### Protected Routes
```http
GET /api/auth/me
Authorization: Bearer eyJhbGci...
```

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable               | Required | Description                              |
|------------------------|----------|------------------------------------------|
| `MONGODB_URI`          | ✅       | MongoDB Atlas connection string          |
| `JWT_SECRET`           | ✅       | JWT signing secret (min 32 chars)        |
| `JWT_REFRESH_SECRET`   | ✅       | Refresh token secret (min 32 chars)      |
| `GMAIL_USER`           | ✅       | Gmail address for sending emails         |
| `GMAIL_APP_PASSWORD`   | ✅       | Gmail App Password (16-char)             |
| `PORT`                 | ✅       | Server port (default: 5000)              |
| `NODE_ENV`             | ✅       | `development` or `production`            |
| `FRONTEND_URL`         | ⚠️       | Frontend URL for CORS                    |
| `APP_URL`              | ⚠️       | Backend URL (used in emails)             |
| `OTP_EXPIRES_MINUTES`  | ⚠️       | OTP TTL in minutes (default: 10)         |

---

## 🔧 Gmail App Password Setup

1. Go to your Google Account → **Security**
2. Enable **2-Step Verification**
3. Go to **App passwords**
4. Select "Mail" + "Other (Custom name)" → `AffiliateEngine`
5. Copy the 16-character password → use as `GMAIL_APP_PASSWORD`

> ⚠️ Never use your actual Gmail password. Always use an App Password.

---

## 🚀 Deploy to Render.com

### Option 1: Auto-deploy with render.yaml
1. Push code to a GitHub repository
2. Go to [render.com](https://render.com) → **New Web Service**
3. Connect your GitHub repo
4. Render will auto-detect `render.yaml`
5. In **Environment Variables**, set:
   - `MONGODB_URI` → your Atlas connection string
   - `GMAIL_USER` → your Gmail address
   - `GMAIL_APP_PASSWORD` → your Gmail App Password
   - `FRONTEND_URL` → your frontend URL

### Option 2: Manual setup
1. **Runtime**: Node
2. **Build Command**: `npm install`
3. **Start Command**: `node src/server.js`
4. **Health Check Path**: `/health`

---

## 🏃 Local Development

```bash
# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env with your values

# Start development server (with hot reload)
npm run dev

# Start production server
npm start
```

---

## 🔒 Security Features

| Feature                    | Implementation                         |
|----------------------------|-----------------------------------------|
| Password hashing           | bcryptjs (12 rounds)                   |
| JWT tokens                 | RS256, issuer + audience validation    |
| Refresh token rotation     | Old token invalidated on each refresh  |
| Rate limiting              | express-rate-limit (auth: 10/15min)    |
| OTP brute force protection | Max 5 failed attempts before lockout   |
| NoSQL injection prevention | express-mongo-sanitize                 |
| XSS + clickjacking headers | helmet.js                              |
| Request size limit         | 10KB max body                          |
| Secure cookies             | httpOnly, secure, sameSite             |

---

## 📦 Tech Stack

- **Runtime**: Node.js ≥ 18
- **Framework**: Express 4
- **Database**: MongoDB Atlas (Mongoose 8)
- **Auth**: JWT (jsonwebtoken) + bcryptjs
- **Email**: Nodemailer + Gmail SMTP
- **Security**: Helmet, CORS, express-rate-limit, express-mongo-sanitize
- **Logging**: Winston
- **Validation**: express-validator
- **Deployment**: Render.com

---

*Built with ❤️ for AffiliateEngine*
