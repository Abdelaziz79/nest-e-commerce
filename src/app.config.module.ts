import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppConfigService } from './app.config.service';
import configurations from './config/configurations';
import { validate } from './config/env.validation'; // ADD THIS

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configurations],
      validate, // ADD THIS - Validates on startup
      validationOptions: {
        allowUnknown: true, // Allow extra env vars
        abortEarly: false, // Show all errors
      },
    }),
  ],
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class AppConfigModule {}
