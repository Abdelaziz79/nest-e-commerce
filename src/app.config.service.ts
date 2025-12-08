// src/app.config.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Configuration } from './config/configurations';

@Injectable()
export class AppConfigService {
  constructor(private readonly configService: ConfigService<Configuration>) {}

  // Application
  get appName() {
    return this.configService.get('appName', { infer: true }) as string;
  }

  get port() {
    return this.configService.get('port') as number;
  }

  get environment() {
    return this.configService.get('environment', { infer: true });
  }

  get isDevelopment() {
    return this.environment === 'development';
  }

  // CORS
  get corsOrigin() {
    return this.configService.get('cors.origin', { infer: true });
  }

  // Database
  get mongodbUri() {
    return this.configService.get('database.mongodbUri', { infer: true });
  }

  // JWT
  get jwtSecret() {
    return this.configService.get('jwt.secret', { infer: true }) as string;
  }

  get jwtExpiration() {
    return this.configService.get('jwt.expiration', { infer: true }) as number;
  }

  get jwtRefreshSecret() {
    return this.configService.get('jwt.refreshSecret', {
      infer: true,
    }) as string;
  }

  get jwtRefreshExpiration() {
    return this.configService.get('jwt.refreshExpiration', {
      infer: true,
    }) as number;
  }

  // Redis
  get redisUri() {
    return this.configService.get('redis.uri', { infer: true });
  }

  get cacheTtl() {
    return this.configService.get('redis.ttl', { infer: true });
  }

  // Rate Limiting
  get throttleTtl() {
    return this.configService.get('throttle.ttl', { infer: true }) as number;
  }

  get throttleLimit() {
    return this.configService.get('throttle.limit', { infer: true }) as number;
  }

  // OAuth - Google
  get googleClientId() {
    return this.configService.get('oauth.google.clientId', { infer: true });
  }

  get googleClientSecret() {
    return this.configService.get('oauth.google.clientSecret', { infer: true });
  }

  get googleCallbackUrl() {
    return this.configService.get('oauth.google.callbackUrl', { infer: true });
  }

  // OAuth - GitHub
  get githubClientId() {
    return this.configService.get('oauth.github.clientId', { infer: true });
  }

  get githubClientSecret() {
    return this.configService.get('oauth.github.clientSecret', { infer: true });
  }

  get githubCallbackUrl() {
    return this.configService.get('oauth.github.callbackUrl', { infer: true });
  }

  get frontendUrl() {
    return this.configService.get('oauth.frontendUrl', { infer: true });
  }

  // Email - Gmail
  get gmailUser() {
    return this.configService.get('email.gmailUser', { infer: true });
  }

  get gmailPassword() {
    return this.configService.get('email.gmailPassword', { infer: true });
  }

  get gmailFromName() {
    return this.configService.get('email.fromName', { infer: true }) as string;
  }

  get gmailReplyTo() {
    return this.configService.get('email.replyTo', { infer: true });
  }
}
