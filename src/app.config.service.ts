// src/app.config.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Configuration } from './config/configurations';

@Injectable()
export class AppConfigService {
  constructor(private readonly configService: ConfigService<Configuration>) {}

  get port() {
    return this.configService.get('port') as number;
  }

  get environment() {
    return this.configService.get('environment', { infer: true });
  }

  get isDevelopment() {
    return this.environment === 'development';
  }

  get corsOrigin() {
    return this.configService.get('cors.origin', { infer: true });
  }

  get mongodbUri() {
    return this.configService.get('database.mongodbUri', { infer: true });
  }

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

  get redisUri() {
    return this.configService.get('redis.uri', { infer: true });
  }

  get cacheTtl() {
    return this.configService.get('redis.ttl', { infer: true });
  }

  get throttleTtl() {
    return this.configService.get('throttle.ttl', { infer: true }) as number;
  }

  get throttleLimit() {
    return this.configService.get('throttle.limit', { infer: true }) as number;
  }
  get googleClientId() {
    return this.configService.get('oauth.google.clientId', { infer: true });
  }
  get googleClientSecret() {
    return this.configService.get('oauth.google.clientSecret', { infer: true });
  }
  get googleCallbackUrl() {
    return this.configService.get('oauth.google.callbackUrl', { infer: true });
  }

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
}
