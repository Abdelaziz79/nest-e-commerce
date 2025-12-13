// src/auth/strategies/jwt.strategy.ts

import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { Cache } from 'cache-manager';
import { AppConfigService } from 'src/config/app.config.service';
import { UserRole, UserStatus } from 'src/users/schemas/user.schema';
import { UsersService } from 'src/users/users.service';

/**
 * JWT payload structure
 */
export interface JwtPayload {
  sub: string; // userId
  email: string;
  role: UserRole;
  status: UserStatus;
  isActive: boolean;
  isEmailVerified: boolean;
  twoFactorEnabled: boolean;
  firstName: string;
  lastName: string;
  iat?: number;
  exp?: number;
}

/**
 * Cached user data for fast validation
 */
interface CachedUserValidation {
  isActive: boolean;
  status: UserStatus;
  role: UserRole;
  isEmailVerified: boolean;
  twoFactorEnabled: boolean;
  firstName: string;
  lastName: string;
}

/**
 * HYBRID JWT STRATEGY
 *
 * Performance Optimization:
 * - Uses Redis cache for user validation data
 * - Cache TTL: 30 seconds (balances performance vs security)
 * - Falls back to DB only if cache miss
 *
 * Security Guarantees:
 * - Banned/suspended users blocked within 30 seconds max
 * - Role changes effective within 30 seconds max
 * - Account deactivation effective within 30 seconds max
 *
 * Best of Both Worlds:
 * - 99%+ requests use cache (no DB hit)
 * - Critical security checks always current within 30s
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly CACHE_TTL = 30000; // 30 seconds
  private readonly CACHE_PREFIX = 'jwt_user:';

  constructor(
    private readonly usersService: UsersService,
    appConfigService: AppConfigService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {
    const jwtSecret = appConfigService.jwtSecret;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in environment variables');
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
      passReqToCallback: false,
    });
  }

  /**
   * Validate JWT with intelligent caching
   *
   * Flow:
   * 1. Check Redis cache (30s TTL) - FAST PATH (99% of requests)
   * 2. If cache miss, query DB and populate cache - SLOW PATH (1% of requests)
   * 3. Validate user status
   * 4. Return user object
   */
  async validate(payload: JwtPayload) {
    // Validate payload structure
    if (!payload.sub || !payload.email || !payload.role) {
      throw new UnauthorizedException('Invalid token payload');
    }

    const userId = payload.sub;
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;

    // TRY CACHE FIRST (FAST PATH - 99% of requests)
    let cachedData =
      await this.cacheManager.get<CachedUserValidation>(cacheKey);

    // CACHE MISS - QUERY DB (SLOW PATH - 1% of requests)
    if (!cachedData) {
      const user = await this.usersService.findByIdMinimal(userId);

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Prepare cache data
      cachedData = {
        isActive: user.isActive,
        status: user.status,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        firstName: user.firstName,
        lastName: user.lastName,
      };

      // Store in cache for 30 seconds
      await this.cacheManager.set(cacheKey, cachedData, this.CACHE_TTL);
    }

    // SECURITY VALIDATIONS (using cached data)
    if (!cachedData.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    if (cachedData.status === UserStatus.BANNED) {
      throw new UnauthorizedException('Account is banned');
    }

    if (cachedData.status === UserStatus.SUSPENDED) {
      throw new UnauthorizedException('Account is suspended');
    }

    // Return user object for @CurrentUser() decorator
    return {
      _id: userId,
      id: userId,
      email: payload.email,
      role: cachedData.role, // Use latest role from cache/DB
      status: cachedData.status,
      isActive: cachedData.isActive,
      isEmailVerified: cachedData.isEmailVerified,
      twoFactorEnabled: cachedData.twoFactorEnabled,
      firstName: cachedData.firstName,
      lastName: cachedData.lastName,
    };
  }
}
