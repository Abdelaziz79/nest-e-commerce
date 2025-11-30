import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { AppConfigService } from './app.config.service'; // Import your service

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 1. Get the Config Service from the app container
  const configService = app.get(AppConfigService);

  // 2. Use configService for CORS
  app.enableCors({
    origin: configService.corsOrigin,
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // 3. Use configService for the Port
  const port = configService.port;

  await app.listen(port);

  console.log(`🚀 Application is running on: http://localhost:${port}`);
  console.log(`🎮 GraphQL Playground: http://localhost:${port}/graphql`);
}
bootstrap();
