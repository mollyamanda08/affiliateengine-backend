/**
 * Authentication API Tests
 * Integration tests for auth endpoints
 */

const request = require('supertest');

// Set test environment before loading app
process.env.NODE_ENV = 'test';
process.env.PORT = '5001';
process.env.JWT_SECRET = 'test-jwt-secret-super-long-key-for-testing-purposes-only';
process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret-super-long-key-for-testing-only';
process.env.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/affiliateengine-test';
process.env.EMAIL_USER = 'test@test.com';
process.env.EMAIL_PASS = 'test-pass';
process.env.BCRYPT_SALT_ROUNDS = '1'; // Faster for tests

const app = require('../app');

describe('AffiliateEngine Auth API', () => {
  describe('GET /health', () => {
    it('should return healthy status', async () => {
      const res = await request(app).get('/health');
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('OK');
    });
  });

  describe('GET /', () => {
    it('should return API info', async () => {
      const res = await request(app).get('/');
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('GET /api', () => {
    it('should return API endpoints list', async () => {
      const res = await request(app).get('/api');
      expect(res.statusCode).toBe(200);
      expect(res.body.endpoints).toBeDefined();
    });
  });

  describe('POST /api/auth/register - Validation', () => {
    it('should fail with missing fields', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({});
      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.errors).toBeDefined();
    });

    it('should fail with invalid email', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'not-an-email',
          password: 'Password1',
          confirmPassword: 'Password1',
        });
      expect(res.statusCode).toBe(400);
      expect(res.body.errors.some((e) => e.field === 'email')).toBe(true);
    });

    it('should fail with weak password (no uppercase)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john@example.com',
          password: 'password1',
          confirmPassword: 'password1',
        });
      expect(res.statusCode).toBe(400);
    });

    it('should fail when passwords do not match', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john@example.com',
          password: 'Password123',
          confirmPassword: 'Password456',
        });
      expect(res.statusCode).toBe(400);
      expect(res.body.errors.some((e) => e.message.includes('match'))).toBe(true);
    });
  });

  describe('POST /api/auth/login - Validation', () => {
    it('should fail with missing credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({});
      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should fail with invalid email format', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'bad-email', password: 'Password1' });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('POST /api/auth/verify-email - Validation', () => {
    it('should fail with missing email and otp', async () => {
      const res = await request(app)
        .post('/api/auth/verify-email')
        .send({});
      expect(res.statusCode).toBe(400);
    });

    it('should fail with non-numeric OTP', async () => {
      const res = await request(app)
        .post('/api/auth/verify-email')
        .send({ email: 'test@example.com', otp: 'abcdef' });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('POST /api/auth/forgot-password - Validation', () => {
    it('should fail with invalid email', async () => {
      const res = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'invalid' });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/auth/me - Protected Route', () => {
    it('should return 401 without token', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 with invalid token', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalidtoken');
      expect(res.statusCode).toBe(401);
    });
  });

  describe('404 Handler', () => {
    it('should return 404 for unknown routes', async () => {
      const res = await request(app).get('/api/unknown-route');
      expect(res.statusCode).toBe(404);
      expect(res.body.success).toBe(false);
    });
  });
});
