// src/auth/auth.service.ts

import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { AppConfigService } from 'src/config/app.config.service';
import { MailQueueService } from 'src/mail/mail-queue.service';
import { NotificationHelperService } from 'src/notifications/notification-helper.service';
import { CreateUserInput } from 'src/users/dto/user.input';
import { User, UserStatus } from '../users/schemas/user.schema';
import { UsersService } from '../users/users.service';
import { OtpService } from './otp.service';
import { OtpType } from './schemas/otp.schema';
import { TwoFactorService } from './services/two-factor.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly appConfigService: AppConfigService,
    private readonly mailQueueService: MailQueueService,
    private readonly otpService: OtpService,
    private readonly twoFactorService: TwoFactorService,
    private readonly notificationHelper: NotificationHelperService,
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

    if (user.status === UserStatus.BANNED) {
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

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      // Generate temporary token for 2FA flow
      const tempToken = await this.twoFactorService.generateTempToken(
        user._id.toString(),
      );

      return {
        requiresTwoFactor: true,
        tempToken,
        message: 'Please provide your 2FA code to complete login',
        accessToken: null,
        refreshToken: null,
        user: null,
      };
    }

    // No 2FA required - complete login
    await this.usersService.updateLastLogin(user._id.toString());

    const tokens = await this.generateTokens(user);
    await this.usersService.addRefreshToken(
      user._id.toString(),
      tokens.refreshToken,
    );

    return {
      ...tokens,
      requiresTwoFactor: false,
      tempToken: null,
      message: null,
    };
  }
  // ===============================================
  // REGISTER WITH EMAIL VERIFICATION
  // ===============================================

  async register(
    createUserInput: CreateUserInput,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    const user = await this.usersService.create(createUserInput);

    const otpCode = await this.otpService.generateOtp(
      user.email,
      OtpType.EMAIL_VERIFICATION,
      {
        userId: user._id.toString(),
        ipAddress: metadata?.ipAddress,
        userAgent: metadata?.userAgent,
      },
    );

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
    const user = await this.usersService.findByEmail(email);

    if (user.isEmailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    await this.otpService.verifyOtp(email, otpCode, OtpType.EMAIL_VERIFICATION);

    //  Set status to ACTIVE when verifying email
    await this.usersService.update(user._id.toString(), {
      isEmailVerified: true,
      status: UserStatus.ACTIVE,
    });

    const updatedUser = await this.usersService.findByEmail(email);

    // SEND NOTIFICATIONS
    try {
      await Promise.all([
        // Welcome notification
        this.notificationHelper.notifyWelcome(updatedUser._id.toString(), {
          firstName: updatedUser.firstName,
          appName: this.appConfigService.appName,
        }),
        // Email verified notification
        this.notificationHelper.notifyEmailVerified(updatedUser._id.toString()),
      ]);
    } catch (notificationError) {
      // Log the error but don't fail the verification
      console.error('Failed to send notifications:', notificationError);
    }

    const tokens = await this.generateTokens(updatedUser);
    await this.usersService.addRefreshToken(
      updatedUser._id.toString(),
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

      const otpCode = await this.otpService.generateOtp(
        email,
        OtpType.PASSWORD_RESET,
        {
          userId: user._id.toString(),
          ipAddress: metadata?.ipAddress,
          userAgent: metadata?.userAgent,
        },
      );

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

      await Promise.all([
        this.mailQueueService.sendPasswordChangedEmail(
          user.email,
          user.firstName,
        ),
        // SEND NOTIFICATION
        this.notificationHelper.notifyPasswordChanged(user._id.toString()),
      ]);

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

      if (type === OtpType.EMAIL_VERIFICATION && user.isEmailVerified) {
        throw new BadRequestException(
          'Email is already verified. No need to resend OTP.',
        );
      }

      await this.otpService.resendOtp(email, type, user.firstName, {
        userId: user._id.toString(),
        ipAddress: metadata?.ipAddress,
        userAgent: metadata?.userAgent,
      });

      return true;
    } catch (error) {
      // If it's a BadRequestException (already verified), re-throw it
      if (error instanceof BadRequestException) {
        throw error;
      }
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
      if (user.status === UserStatus.BANNED) {
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
      status: UserStatus.ACTIVE, // Social login users are active immediately
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

  // ===============================================
  // HELPER FUNCTIONS
  // ===============================================

  /**
   * Complete 2FA login and generate tokens
   * This is called after 2FA verification is complete
   */
  async complete2FALogin(userId: string) {
    const user = await this.usersService.findById(userId);

    await this.usersService.updateLastLogin(userId);

    const tokens = await this.generateTokens(user as any);
    await this.usersService.addRefreshToken(userId, tokens.refreshToken);

    return tokens;
  }
}
