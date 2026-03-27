require('dotenv').config();

const app = require('./app');
const connectDB = require('./config/database');
const logger = require('./utils/logger');

const PORT = parseInt(process.env.PORT || '5000', 10);
const HOST = '0.0.0.0'; // Required for Render.com

// ─── Uncaught Exception Handler ───────────────────────────────────────────────
process.on('uncaughtException', (error) => {
  logger.error(`UNCAUGHT EXCEPTION: ${error.message}`, { stack: error.stack });
  logger.error('Shutting down due to uncaught exception...');
  process.exit(1);
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const startServer = async () => {
  try {
    // Connect to MongoDB Atlas
    await connectDB();

    // Start HTTP server
    const server = app.listen(PORT, HOST, () => {
      logger.info(`🚀 AffiliateEngine API running on port ${PORT}`);
      logger.info(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`🌐 Health check: http://${HOST}:${PORT}/health`);
    });

    // ─── Unhandled Promise Rejections ───────────────────────────────
    process.on('unhandledRejection', (reason, promise) => {
      logger.error(`UNHANDLED REJECTION at: ${promise}`, { reason });
      // Graceful shutdown
      server.close(() => {
        logger.error('Server closed due to unhandled rejection.');
        process.exit(1);
      });
    });

    // ─── Graceful Shutdown (SIGTERM from Render.com) ──────────────
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received. Starting graceful shutdown...');
      server.close(() => {
        logger.info('HTTP server closed.');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      logger.info('SIGINT received. Shutting down...');
      server.close(() => {
        logger.info('HTTP server closed.');
        process.exit(0);
      });
    });

    return server;
  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`);
    process.exit(1);
  }
};

startServer();
