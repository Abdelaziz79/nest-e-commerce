import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Configurations } from './config/configurations';

@Injectable()
export class AppConfigService {
  constructor(private readonly configService: ConfigService<Configurations>) {}
  get port() {
    return this.configService.get('port', { infer: true }) as number;
  }

  get environment() {
    return this.configService.get('environment', { infer: true });
  }

  get isDevelopment() {
    return this.environment === 'development';
  }

  get mongodbUri() {
    return this.configService.get('database.mongodbUri', { infer: true });
  }

  get jwtSecret() {
    return this.configService.get('jwt.secret', { infer: true });
  }

  get jwtExpiration() {
    return this.configService.get('jwt.expiration', { infer: true }) as number;
  }

  get corsOrigin() {
    return this.configService.get('cors.origin', { infer: true });
  }
}
