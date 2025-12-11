import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import basicAuth from 'express-basic-auth';
import { graphqlUploadExpress } from 'graphql-upload-ts';
import helmet from 'helmet';
import { join } from 'path';
import { AppModule } from './app.module';
import { SanitizePipe } from './common/pipes/sanitize.pipe';
import { AppConfigService } from './config/app.config.service';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });

  const configService = app.get(AppConfigService);
  const logger = new Logger('Bootstrap');
  const isDev = configService.isDevelopment;

  if (!isDev) {
    app.useLogger(['error', 'warn']);
  }

  app.use(
    graphqlUploadExpress({
      maxFileSize: 10 * 1024 * 1024, // 10MB max file size
      maxFiles: 10, // Max 10 files per request
    }),
  );

  // Serve static files (uploaded files)
  app.useStaticAssets(join(__dirname, '..', 'uploads'), {
    prefix: '/uploads/',
    maxAge: isDev ? 0 : 31536000000,
    setHeaders: (res, path) => {
      res.set('Cross-Origin-Resource-Policy', 'cross-origin');
      res.set('Access-Control-Allow-Origin', '*');

      if (path.endsWith('.webp')) {
        res.set('Content-Type', 'image/webp');
      }
    },
  });

  // Secure Bull Board with Basic Auth (only in production)
  if (!isDev) {
    app.use(
      '/admin/queues',
      basicAuth({
        users: {
          admin: configService.bullBoardPassword,
        },
        challenge: true,
        realm: 'Bull Board Admin',
      }),
    );
  }

  // Production-ready Helmet configuration
  app.use(
    helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: isDev
        ? {
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
            directives: {
              defaultSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              scriptSrc: ["'self'", "'unsafe-inline'"],
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
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      noSniff: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    }),
  );

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

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

  app.useGlobalPipes(
    new SanitizePipe(),
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
      disableErrorMessages: !isDev,
      stopAtFirstError: !isDev,
    }),
  );

  app.enableShutdownHooks();

  const port = configService.port;
  await app.listen(port);

  if (isDev) {
    logger.log(`🚀 Application is running on: http://localhost:${port}`);
    logger.log(`🎮 GraphQL Playground: http://localhost:${port}/graphql`);
    logger.log(
      `📊 Bull Board Dashboard: http://localhost:${port}/admin/queues`,
    );
  } else {
    logger.log(`🚀 Application started on port ${port}`);
    logger.log(`📊 Bull Board: /admin/queues (Basic Auth Required)`);
  }

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  });

  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
  });
}

bootstrap();
