const configurations = () => ({
  port: parseInt(process.env.PORT || '5000', 10),
  environment: process.env.ENVIRONMENT || 'development',
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  },
  database: {
    mongodbUri:
      process.env.MONGODB_URI || 'mongodb://localhost:27017/nest-e-commerce',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'default_jwt_secret',
    expiration: process.env.JWT_EXPIRATION || '14d',
  },
});
export default configurations;

export type Configurations = ReturnType<typeof configurations>;
