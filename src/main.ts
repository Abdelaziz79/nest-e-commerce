// src/main.ts - PRODUCTION-READY VERSION
import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import { AppConfigService } from './app.config.service';
import { AppModule } from './app.module';
import { SanitizePipe } from './common/pipes/sanitize.pipe';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    // ✅ Disable NestJS logger in production, use custom logger
    logger:
      process.env.NODE_ENV === 'production'
        ? ['error', 'warn']
        : ['log', 'error', 'warn', 'debug', 'verbose'],
  });

  const configService = app.get(AppConfigService);
  const logger = new Logger('Bootstrap');
  const isDev = configService.isDevelopment;

  // ✅ Production-ready Helmet configuration
  app.use(
    helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: isDev
        ? {
            // Development: Allow Apollo Sandbox
            directives: {
              defaultSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              scriptSrc: [
                "'self'",
                "'unsafe-inline'",
                'https:',
                'cdn.jsdelivr.net',
                'embeddable-sandbox.cdn.apollographql.com',
              ],
              imgSrc: [
                "'self'",
                'data:',
                'https:',
                'apollo-server-landing-page.cdn.apollographql.com',
              ],
              connectSrc: ["'self'"],
              fontSrc: ["'self'", 'fonts.gstatic.com'],
              objectSrc: ["'none'"],
              mediaSrc: ["'self'"],
              frameSrc: ["'self'", 'sandbox.embed.apollographql.com'],
              manifestSrc: [
                "'self'",
                'apollo-server-landing-page.cdn.apollographql.com',
              ],
            },
          }
        : {
            // Production: Strict CSP
            directives: {
              defaultSrc: ["'self'"],
              styleSrc: ["'self'"],
              scriptSrc: ["'self'"],
              imgSrc: [
                "'self'",
                'data:',
                'https://apollo-server-landing-page.cdn.apollographql.com',
              ],
              connectSrc: ["'self'"],
              fontSrc: ["'self'"],
              objectSrc: ["'none'"],
              mediaSrc: ["'self'"],
              frameSrc: ["'none'"],
              baseUri: ["'self'"],
              formAction: ["'self'"],
              frameAncestors: ["'none'"],
            },
          },
      // ✅ Additional security headers
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      },
      noSniff: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    }),
  );

  // ✅ Trust proxy (required for production behind load balancers)
  app.set('trust proxy', 1);

  // ✅ Disable X-Powered-By header
  app.disable('x-powered-by');

  // ✅ Production-safe CORS
  app.enableCors({
    origin: configService.corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'apollo-require-preflight',
      'X-Requested-With',
    ],
    exposedHeaders: ['X-Total-Count'],
    maxAge: 3600,
  });

  // ✅ Global pipes with proper validation
  app.useGlobalPipes(
    new SanitizePipe(), // First: Sanitize input
    new ValidationPipe({
      // Second: Validate
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
      disableErrorMessages: !isDev, // Hide detailed validation errors in production
      stopAtFirstError: !isDev, // Fail fast in production
    }),
  );

  // ✅ Graceful shutdown
  app.enableShutdownHooks();

  const port = configService.port;

  await app.listen(port);

  // ✅ Use logger instead of console.log
  if (isDev) {
    logger.log(`🚀 Application is running on: http://localhost:${port}`);
    logger.log(`🎮 GraphQL Playground: http://localhost:${port}/graphql`);
  } else {
    logger.log(`🚀 Application started on port ${port}`);
  }

  // ✅ Handle unhandled rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit the process in production, log and monitor
  });

  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    // In production, you might want to gracefully shutdown
    process.exit(1);
  });
}

bootstrap();
