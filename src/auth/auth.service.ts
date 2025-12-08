// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { AppConfigService } from 'src/app.config.service';
import { MailService } from 'src/mail/mail.service';
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
    private readonly mailService: MailService,
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
    // Check if account is locked
    const isLocked = await this.usersService.isAccountLocked(email);
    if (isLocked) {
      throw new UnauthorizedException(
        'Account is temporarily locked due to failed attempts',
      );
    }

    // Find user
    const user = await this.usersService.findByEmail(email);

    // Check if user is active
    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    // Check if user is banned
    if (user.status === 'banned') {
      throw new UnauthorizedException(`Account is banned: ${user.banReason}`);
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      throw new UnauthorizedException(
        'Please verify your email before logging in. Check your inbox for the verification code.',
      );
    }

    // Validate password
    const isPasswordValid = await user.validatePassword(password);
    if (!isPasswordValid) {
      await this.usersService.incrementLoginAttempts(email);

      // Check if account should be locked after this attempt
      const updatedUser = await this.usersService.findByEmail(email);
      if (updatedUser.lockUntil && updatedUser.lockUntil > new Date()) {
        await this.mailService.sendAccountLockedEmail(
          email,
          user.firstName,
          updatedUser.lockUntil,
        );
      }

      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset login attempts on successful login
    await this.usersService.updateLastLogin(user._id.toString());

    // Generate tokens
    const tokens = await this.generateTokens(user);
    await this.usersService.addRefreshToken(
      user._id.toString(),
      tokens.refreshToken,
    );

    return tokens;
  }

  // ===============================================
  // REGISTER WITH EMAIL VERIFICATION
  // ===============================================

  async register(
    createUserInput: CreateUserInput,
    metadata?: { ipAddress?: string; userAgent?: string },
  ) {
    const user = await this.usersService.create(createUserInput);

    // Generate OTP and send welcome email with verification code
    const otpCode = await this.otpService.generateAndSendOtp(
      user.email,
      OtpType.EMAIL_VERIFICATION,
      user.firstName,
      {
        userId: user._id.toString(),
        ipAddress: metadata?.ipAddress,
        userAgent: metadata?.userAgent,
      },
    );

    // Send combined welcome + verification email
    await this.mailService.sendWelcomeWithVerificationEmail(
      user.email,
      user.firstName,
      otpCode,
    );

    return {
      success: true,
      message:
        'Registration successful! Please check your email for the verification code.',
      email: user.email,
    };
  }

  /**
   * Verify email with OTP
   */
  async verifyEmail(email: string, otpCode: string) {
    // Verify OTP
    await this.otpService.verifyOtp(email, otpCode, OtpType.EMAIL_VERIFICATION);

    // Update user's email verification status
    const user = await this.usersService.findByEmail(email);
    await this.usersService.update(user._id.toString(), {
      // @ts-ignore
      isEmailVerified: true,
    });

    // Generate tokens for auto-login after verification
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

      // Generate and send OTP
      await this.otpService.generateAndSendOtp(
        email,
        OtpType.PASSWORD_RESET,
        user.firstName,
        {
          userId: user._id.toString(),
          ipAddress: metadata?.ipAddress,
          userAgent: metadata?.userAgent,
        },
      );

      return true;
    } catch (error) {
      // Always return true to prevent email enumeration
      return true;
    }
  }

  async resetPasswordWithOtp(
    email: string,
    otpCode: string,
    newPassword: string,
  ): Promise<boolean> {
    try {
      // Verify OTP
      await this.otpService.verifyOtp(email, otpCode, OtpType.PASSWORD_RESET);

      // Get user
      const user = await this.usersService.findByEmail(email);

      // Update password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.usersService.updatePassword(
        user._id.toString(),
        hashedPassword,
      );

      // Revoke all refresh tokens
      await this.usersService.revokeAllRefreshTokens(user._id.toString());

      // Send password changed confirmation email
      await this.mailService.sendPasswordChangedEmail(
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
      // Return true to prevent email enumeration
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
    // 1. Check if user exists by Social ID
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

    // 2. Check if user exists by Email (Account Linking)
    try {
      user = await this.usersService.findByEmail(details.email);
    } catch {
      user = null;
    }

    if (user) {
      if (!user.isActive) {
        throw new UnauthorizedException('Account is deactivated');
      }

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

    // 3. Create new user (social accounts are auto-verified)
    const randomPassword = crypto.randomBytes(16).toString('hex') + 'A1!';

    const newUser = await this.usersService.create({
      email: details.email,
      firstName: details.firstName || 'User',
      lastName: details.lastName || 'Social',
      password: randomPassword,
      avatar: details.picture,
      isEmailVerified: true, // Auto-verify social logins
    } as any);

    // Link social account
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

    // Send simple welcome email (no verification needed for social logins)
    await this.mailService.sendWelcomeEmail(user.email, user.firstName);

    return user;
  }
}
