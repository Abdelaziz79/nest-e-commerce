// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { AppConfigService } from 'src/app.config.service';
import { CreateUserInput } from 'src/users/dto/user.input'; // Ensure correct import path
import { User } from '../users/schemas/user.schema';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly appConfigService: AppConfigService,
  ) {}

  // ===============================================
  // JWT & SESSION MANAGEMENT
  // ===============================================

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

    await this.usersService.updateLastLogin(user._id.toString());

    const tokens = await this.generateTokens(user);
    await this.usersService.addRefreshToken(
      user._id.toString(),
      tokens.refreshToken,
    );

    return tokens;
  }

  async register(createUserInput: CreateUserInput) {
    const user = await this.usersService.create(createUserInput);
    const tokens = await this.generateTokens(user);
    await this.usersService.addRefreshToken(
      user._id.toString(),
      tokens.refreshToken,
    );
    return tokens;
  }

  async refreshTokens(refreshToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.appConfigService.jwtRefreshSecret,
      });

      const user = await this.usersService.findById(payload.sub);

      // Safe cast to User because we know the structure fits what generateTokens needs
      const tokens = await this.generateTokens(user as any);

      await this.usersService.rotateRefreshToken(
        user._id.toString(),
        refreshToken,
        tokens.refreshToken,
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

  // ===============================================
  // SOCIAL LOGIN LOGIC (Called by Strategies)
  // ===============================================

  async validateSocialUser(details: {
    socialId: string;
    email: string;
    firstName: string;
    lastName: string;
    picture: string;
    provider: 'google' | 'github';
  }): Promise<User> {
    // 1. Check if user exists by Social ID
    let user =
      details.provider === 'google'
        ? await this.usersService.findByGoogleId(details.socialId)
        : await this.usersService.findByGithubId(details.socialId);

    if (user) {
      // Check for ban/deactivation even on social login
      if (!user.isActive)
        throw new UnauthorizedException('Account is deactivated');
      if (user.status === 'banned')
        throw new UnauthorizedException('Account is banned');

      // Update avatar if missing
      if (!user.avatar && details.picture) {
        await this.usersService.update(user._id.toString(), {
          avatar: details.picture,
        });
      }

      await this.usersService.updateLastLogin(user._id.toString());
      return user;
    }

    // 2. Check if user exists by Email (Account Linking)
    try {
      user = await this.usersService.findByEmail(details.email);
    } catch {
      user = null;
    }

    if (user) {
      // Ensure we don't link to banned accounts
      if (!user.isActive)
        throw new UnauthorizedException('Account is deactivated');

      // Link account
      if (details.provider === 'google') {
        user = await this.usersService.linkGoogleAccount(
          user._id.toString(),
          details.socialId,
        );
      } else {
        user = await this.usersService.linkGithubAccount(
          user._id.toString(),
          details.socialId,
        );
      }

      await this.usersService.updateLastLogin(user._id.toString());
      return user;
    }

    // 3. Create new user
    const randomPassword = crypto.randomBytes(16).toString('hex') + 'A1!';

    // We cast to 'any' to bypass DTO restrictions (like isEmailVerified)
    return this.usersService
      .create({
        email: details.email,
        firstName: details.firstName || 'User',
        lastName: details.lastName || 'Social',
        password: randomPassword,
        avatar: details.picture,
        isEmailVerified: true,
      } as any)
      .then(async (newUser) => {
        if (details.provider === 'google') {
          return this.usersService.linkGoogleAccount(
            newUser._id.toString(),
            details.socialId,
          );
        } else {
          return this.usersService.linkGithubAccount(
            newUser._id.toString(),
            details.socialId,
          );
        }
      });
  }

  // ===============================================
  // RESET PASSWORD
  // ===============================================

  generateVerificationToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  generatePasswordResetToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  async requestPasswordReset(email: string): Promise<boolean> {
    try {
      const user = await this.usersService.findByEmail(email);

      const rawToken = this.generatePasswordResetToken();
      const hashedToken = await bcrypt.hash(rawToken, 10);

      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1);

      await this.usersService.setPasswordResetToken(
        user._id.toString(),
        hashedToken,
        expiresAt,
      );

      const compositeToken = Buffer.from(
        `${user._id.toString()}:${rawToken}`,
      ).toString('base64url');

      // TODO: Replace with MailService call
      console.log(`[RESET LINK] ?token=${compositeToken}`);

      return true;
    } catch (error) {
      return true;
    }
  }

  async resetPassword(token: string, newPassword: string): Promise<boolean> {
    try {
      const decoded = Buffer.from(token, 'base64url').toString('utf-8');
      const [userId, rawToken] = decoded.split(':');

      if (!userId || !rawToken) {
        throw new Error('Invalid structure');
      }

      const user = await this.usersService.findByIdForPasswordReset(userId);

      if (!user) {
        throw new UnauthorizedException('Invalid or expired reset token');
      }

      const isValid = await bcrypt.compare(rawToken, user.passwordResetToken);
      if (!isValid) {
        throw new UnauthorizedException('Invalid reset token');
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.usersService.updatePassword(userId, hashedPassword);
      await this.usersService.revokeAllRefreshTokens(userId);

      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }
  }
}
