// src/config/configurations.ts
const configuration = () => ({
  // Application
  appName: process.env.APP_NAME || 'NestJS E-Commerce',
  port: parseInt(process.env.PORT || '5000', 10),
  environment: process.env.ENVIRONMENT || process.env.NODE_ENV || 'development',

  // Redis
  redis: {
    uri: process.env.REDIS_URI || 'redis://localhost:6379',
    ttl: parseInt(process.env.CACHE_TTL || '30000', 10),
  },

  // CORS
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  },

  // Database
  database: {
    mongodbUri:
      process.env.MONGODB_URI || 'mongodb://localhost:27017/nest-e-commerce',
  },

  // JWT
  jwt: {
    secret: process.env.JWT_SECRET || 'default_jwt_secret',
    expiration: process.env.JWT_EXPIRATION || '15m',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'default_refresh_secret',
    refreshExpiration: process.env.JWT_REFRESH_EXPIRATION || '7d',
  },

  // Rate Limiting
  throttle: {
    ttl: parseInt(process.env.THROTTLE_TTL || '60000', 10),
    limit: parseInt(process.env.THROTTLE_LIMIT || '20', 10),
  },

  // OAuth
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackUrl:
        process.env.GOOGLE_CALLBACK_URL ||
        'http://localhost:5000/auth/google/callback',
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackUrl:
        process.env.GITHUB_CALLBACK_URL ||
        'http://localhost:5000/auth/github/callback',
    },
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
  },

  // Email (Gmail/Google)
  email: {
    gmailUser: process.env.GMAIL_USER,
    gmailPassword: process.env.GMAIL_APP_PASSWORD,
    fromName: process.env.GMAIL_FROM_NAME || 'NestJS E-Commerce',
    replyTo: process.env.GMAIL_REPLY_TO,
  },
});

export default configuration;

export type Configuration = ReturnType<typeof configuration>;
