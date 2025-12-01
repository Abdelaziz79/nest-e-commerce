// src/config/configurations.ts
const configuration = () => ({
  port: parseInt(process.env.PORT || '5000', 10),
  environment: process.env.ENVIRONMENT || 'development',
  redis: {
    uri: process.env.REDIS_URI || 'redis://localhost:6379',
    ttl: parseInt(process.env.CACHE_TTL || '30000', 10), // Default 30 seconds
  },
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  },
  database: {
    mongodbUri:
      process.env.MONGODB_URI || 'mongodb://localhost:27017/nest-e-commerce',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'default_jwt_secret',
    expiration: process.env.JWT_EXPIRATION || '15m', // Access Token (Short)
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'default_refresh_secret',
    refreshExpiration: process.env.JWT_REFRESH_EXPIRATION || '7d', // Refresh Token (Long)
  },
});
export default configuration;

export type Configuration = ReturnType<typeof configuration>;
