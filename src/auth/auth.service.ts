// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { AppConfigService } from 'src/app.config.service';
import { User } from '../users/schemas/user.schema';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly appConfigService: AppConfigService,
  ) {}

  // Helper: Generate Tokens
  async generateTokens(user: User) {
    const payload = {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.appConfigService.jwtSecret,
        expiresIn: this.appConfigService.jwtExpiration,
      }),
      this.jwtService.signAsync(payload, {
        secret: this.appConfigService.jwtRefreshSecret,
        expiresIn: this.appConfigService.jwtRefreshExpiration,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      user: {
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    };
  }

  async login(email: string, password: string) {
    // 1. Validations
    const isLocked = await this.usersService.isAccountLocked(email);
    if (isLocked)
      throw new UnauthorizedException(
        'Account is temporarily locked due to failed attempts',
      );

    const user = await this.usersService.findByEmail(email);

    if (!user.isActive)
      throw new UnauthorizedException('Account is deactivated');
    if (user.status === 'banned')
      throw new UnauthorizedException(`Account is banned: ${user.banReason}`);

    const isPasswordValid = await user.validatePassword(password);
    if (!isPasswordValid) {
      await this.usersService.incrementLoginAttempts(email);
      throw new UnauthorizedException('Invalid credentials');
    }

    // 2. Success Logic
    await this.usersService.updateLastLogin(user._id.toString());

    // 3. Generate & Save Token
    const tokens = await this.generateTokens(user);
    await this.usersService.addRefreshToken(
      user._id.toString(),
      tokens.refreshToken,
    );

    return tokens;
  }

  async register(createUserInput: any) {
    const user = await this.usersService.create(createUserInput);
    const tokens = await this.generateTokens(user);
    await this.usersService.addRefreshToken(
      user._id.toString(),
      tokens.refreshToken,
    );
    return tokens;
  }

  // Look how clean this is now!
  async refreshTokens(refreshToken: string) {
    try {
      // 1. Verify Signature
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.appConfigService.jwtRefreshSecret,
      });

      // 2. Generate New Tokens (We need the new one to rotate)
      // Note: We need to fetch the user first to generate tokens
      const user = await this.usersService.findById(payload.sub);

      const tokens = await this.generateTokens(user);

      // 3. Perform Rotation (Atomic-like in UsersService)
      await this.usersService.rotateRefreshToken(
        user._id.toString(),
        refreshToken, // Old
        tokens.refreshToken, // New
      );

      return tokens;
    } catch (e) {
      throw new UnauthorizedException('Invalid or Expired Refresh Token');
    }
  }

  async logout(userId: string, refreshToken: string) {
    await this.usersService.revokeRefreshToken(userId, refreshToken);
    return true;
  }

  generateVerificationToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  generatePasswordResetToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}
