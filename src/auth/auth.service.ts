// src/auth/auth.service.ts - FIXED VERSION

import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { AppConfigService } from 'src/config/app.config.service';
import { MailQueueService } from 'src/mail/mail-queue.service';
import { CreateUserInput } from 'src/users/dto/user.input';
import { User } from '../users/schemas/user.schema';
import { UsersService } from '../users/users.service';
import { OtpService } from './otp.service';
import { OtpType } from './schemas/otp.schema';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly appConfigService: AppConfigService,
    private readonly mailQueueService: MailQueueService,
    private readonly otpService: OtpService,
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

  // ===============================================
  // SIMPLE LOGIN (EMAIL + PASSWORD)
  // ===============================================

  async login(email: string, password: string) {
    const isLocked = await this.usersService.isAccountLocked(email);
    if (isLocked) {
      throw new UnauthorizedException(
        'Account is temporarily locked due to failed attempts',
      );
    }

    const user = await this.usersService.findByEmail(email);

    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    if (user.status === 'banned') {
      throw new UnauthorizedException(`Account is banned: ${user.banReason}`);
    }

    if (!user.isEmailVerified) {
      throw new UnauthorizedException(
        'Please verify your email before logging in.',
      );
    }

    const isPasswordValid = await user.validatePassword(password);
    if (!isPasswordValid) {
      await this.usersService.incrementLoginAttempts(email);

      const updatedUser = await this.usersService.findByEmail(email);
      if (updatedUser.lockUntil && updatedUser.lockUntil > new Date()) {
        await this.mailQueueService.sendAccountLockedEmail(
          email,
          user.firstName,
          updatedUser.lockUntil,
        );
      }

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

  // ===============================================
  // ✅ FIXED: REGISTER WITH EMAIL VERIFICATION
  // ===============================================

  async register(
    createUserInput: CreateUserInput,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    const user = await this.usersService.create(createUserInput);

    // ✅ FIX: Generate OTP but DON'T send email yet
    const otpCode = await this.otpService.generateOtp(
      user.email,
      OtpType.EMAIL_VERIFICATION,
      {
        userId: user._id.toString(),
        ipAddress: metadata?.ipAddress,
        userAgent: metadata?.userAgent,
      },
    );

    // ✅ FIX: Send ONLY ONE email with both welcome message + OTP
    await this.mailQueueService.sendWelcomeWithVerification(
      user.email,
      user.firstName,
      otpCode,
    );

    return {
      success: true,
      message: 'Registration successful! Check your email for verification.',
      email: user.email,
    };
  }

  async verifyEmail(email: string, otpCode: string) {
    await this.otpService.verifyOtp(email, otpCode, OtpType.EMAIL_VERIFICATION);

    const user = await this.usersService.findByEmail(email);
    await this.usersService.update(user._id.toString(), {
      // @ts-ignore
      isEmailVerified: true,
    });

    const tokens = await this.generateTokens(user);
    await this.usersService.addRefreshToken(
      user._id.toString(),
      tokens.refreshToken,
    );

    return tokens;
  }

  // ===============================================
  // PASSWORD RESET WITH OTP
  // ===============================================

  async requestPasswordReset(
    email: string,
    metadata?: { ipAddress?: string; userAgent?: string },
  ): Promise<boolean> {
    try {
      const user = await this.usersService.findByEmail(email);

      // ✅ Use the new method that only generates OTP
      const otpCode = await this.otpService.generateOtp(
        email,
        OtpType.PASSWORD_RESET,
        {
          userId: user._id.toString(),
          ipAddress: metadata?.ipAddress,
          userAgent: metadata?.userAgent,
        },
      );

      // ✅ Queue the email separately
      await this.mailQueueService.sendPasswordResetOtp(
        email,
        user.firstName,
        otpCode,
      );

      return true;
    } catch (error) {
      return true; // Prevent email enumeration
    }
  }

  async resetPasswordWithOtp(
    email: string,
    otpCode: string,
    newPassword: string,
  ): Promise<boolean> {
    try {
      await this.otpService.verifyOtp(email, otpCode, OtpType.PASSWORD_RESET);

      const user = await this.usersService.findByEmail(email);

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.usersService.updatePassword(
        user._id.toString(),
        hashedPassword,
      );

      await this.usersService.revokeAllRefreshTokens(user._id.toString());

      await this.mailQueueService.sendPasswordChangedEmail(
        user.email,
        user.firstName,
      );

      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }
  }

  // ===============================================
  // RESEND OTP
  // ===============================================

  async resendOtp(
    email: string,
    type: OtpType,
    metadata?: { ipAddress?: string; userAgent?: string },
  ): Promise<boolean> {
    try {
      const user = await this.usersService.findByEmail(email);

      await this.otpService.resendOtp(email, type, user.firstName, {
        userId: user._id.toString(),
        ipAddress: metadata?.ipAddress,
        userAgent: metadata?.userAgent,
      });

      return true;
    } catch (error) {
      return true;
    }
  }

  // ===============================================
  // TOKEN REFRESH & LOGOUT
  // ===============================================

  async refreshTokens(refreshToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.appConfigService.jwtRefreshSecret,
      });

      const user = await this.usersService.findById(payload.sub);
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
  // SOCIAL LOGIN LOGIC
  // ===============================================

  async validateSocialUser(details: {
    socialId: string;
    email: string;
    firstName: string;
    lastName: string;
    picture: string;
    provider: 'google' | 'github';
  }): Promise<User> {
    let user =
      details.provider === 'google'
        ? await this.usersService.findByGoogleId(details.socialId)
        : await this.usersService.findByGithubId(details.socialId);

    if (user) {
      if (!user.isActive) {
        throw new UnauthorizedException('Account is deactivated');
      }
      if (user.status === 'banned') {
        throw new UnauthorizedException('Account is banned');
      }

      if (!user.avatar && details.picture) {
        await this.usersService.update(user._id.toString(), {
          avatar: details.picture,
        });
      }

      await this.usersService.updateLastLogin(user._id.toString());
      return user;
    }

    try {
      user = await this.usersService.findByEmail(details.email);
    } catch {
      user = null;
    }

    if (user) {
      if (!user.isActive) {
        throw new UnauthorizedException('Account is deactivated');
      }

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

    const randomPassword = crypto.randomBytes(16).toString('hex') + 'A1!';

    const newUser = await this.usersService.create({
      email: details.email,
      firstName: details.firstName || 'User',
      lastName: details.lastName || 'Social',
      password: randomPassword,
      avatar: details.picture,
      isEmailVerified: true,
    } as any);

    if (details.provider === 'google') {
      user = await this.usersService.linkGoogleAccount(
        newUser._id.toString(),
        details.socialId,
      );
    } else {
      user = await this.usersService.linkGithubAccount(
        newUser._id.toString(),
        details.socialId,
      );
    }

    await this.mailQueueService.sendWelcomeEmail(user.email, user.firstName);

    return user;
  }
}
