// src/common/guards/user-rate-limit.guard.ts

import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import type { Cache } from 'cache-manager';

@Injectable()
export class UserRateLimitGuard implements CanActivate {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = GqlExecutionContext.create(context);
    const { req } = ctx.getContext();

    const user = req.user;
    if (!user) return true; // Not authenticated, let other guards handle

    const userId = user._id.toString();
    const key = `user-rate-limit:${userId}`;

    const current = (await this.cacheManager.get<number>(key)) || 0;

    // Allow 100 requests per minute per user
    if (current >= 100) {
      throw new HttpException(
        'Too many requests. Please try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    await this.cacheManager.set(key, current + 1, 60000); // 1 minute TTL
    return true;
  }
}
