// src/config/env.validation.ts
import { plainToInstance } from 'class-transformer';
import {
  IsEnum,
  IsNumber,
  IsString,
  validateSync,
  IsOptional,
  Min,
  Max,
  Matches,
  IsEmail,
} from 'class-validator';

enum Environment {
  Development = 'development',
  Production = 'production',
  Test = 'test',
  Staging = 'staging',
}

class EnvironmentVariables {
  // Application
  @IsOptional()
  @IsString()
  APP_NAME?: string;

  @IsEnum(Environment)
  ENVIRONMENT: Environment;

  @IsNumber()
  @Min(1000)
  @Max(65535)
  PORT: number;

  // Database
  @IsString()
  @Matches(/^mongodb:\/\/.+/, {
    message: 'MONGODB_URI must be a valid MongoDB connection string',
  })
  MONGODB_URI: string;

  @IsString()
  @Matches(/^redis:\/\/.+/, {
    message: 'REDIS_URI must be a valid Redis connection string',
  })
  REDIS_URI: string;

  @IsNumber()
  @Min(1000)
  @Max(3600000)
  CACHE_TTL: number;

  // JWT
  @IsString()
  JWT_SECRET: string;

  @IsString()
  JWT_EXPIRATION: string;

  @IsString()
  JWT_REFRESH_SECRET: string;

  @IsString()
  JWT_REFRESH_EXPIRATION: string;

  // CORS
  @IsString()
  CORS_ORIGIN: string;

  // Rate Limiting
  @IsNumber()
  @Min(1000)
  THROTTLE_TTL: number;

  @IsNumber()
  @Min(1)
  @Max(1000)
  THROTTLE_LIMIT: number;

  // OAuth - Optional
  @IsOptional()
  @IsString()
  GOOGLE_CLIENT_ID?: string;

  @IsOptional()
  @IsString()
  GOOGLE_CLIENT_SECRET?: string;

  @IsOptional()
  @IsString()
  GOOGLE_CALLBACK_URL?: string;

  @IsOptional()
  @IsString()
  GITHUB_CLIENT_ID?: string;

  @IsOptional()
  @IsString()
  GITHUB_CLIENT_SECRET?: string;

  @IsOptional()
  @IsString()
  GITHUB_CALLBACK_URL?: string;

  @IsOptional()
  @IsString()
  FRONTEND_URL?: string;

  // Email (Gmail) - Optional but recommended
  @IsOptional()
  @IsEmail()
  GMAIL_USER?: string;

  @IsOptional()
  @IsString()
  GMAIL_APP_PASSWORD?: string;

  @IsOptional()
  @IsString()
  GMAIL_FROM_NAME?: string;

  @IsOptional()
  @IsEmail()
  GMAIL_REPLY_TO?: string;
}

export function validate(config: Record<string, unknown>) {
  const validatedConfig = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });

  if (errors.length > 0) {
    throw new Error(
      `❌ Environment validation failed:\n${errors
        .map((err) => {
          const constraints = err.constraints || {};
          return `  - ${err.property}: ${Object.values(constraints).join(', ')}`;
        })
        .join('\n')}`,
    );
  }

  return validatedConfig;
}
