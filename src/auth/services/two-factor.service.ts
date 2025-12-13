// src/auth/services/two-factor.service.ts

import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as QRCode from 'qrcode';
import * as speakeasy from 'speakeasy';
import { AppConfigService } from 'src/config/app.config.service';
import { UsersService } from 'src/users/users.service';
import { JwtPayload } from '../strategies/jwt.strategy';

/**
 * TWO-FACTOR AUTHENTICATION SERVICE
 * NO CIRCULAR DEPENDENCY - Uses JwtService directly
 */
@Injectable()
export class TwoFactorService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: AppConfigService,
    private readonly usersService: UsersService,
  ) {}

  // ==========================================
  // SETUP 2FA
  // ==========================================

  async initiate2FASetup(
    userId: string,
    email: string,
    password: string,
  ): Promise<{
    secret: string;
    qrCode: string;
    manualEntryKey: string;
    message: string;
  }> {
    const user = await this.usersService.findByEmail(email);
    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    return this.generateTwoFactorSecret(userId);
  }

  private async generateTwoFactorSecret(userId: string) {
    const user = await this.usersService.findById(userId);

    const secret = speakeasy.generateSecret({
      name: `${this.configService.appName} (${user.email})`,
      issuer: this.configService.appName,
      length: 32,
    });

    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

    await this.usersService.updateTwoFactorSecret(userId, secret.base32);

    return {
      secret: secret.base32,
      qrCode: qrCodeDataUrl,
      manualEntryKey: secret.base32,
      message:
        'Scan the QR code with your authenticator app and verify with a code to enable 2FA',
    };
  }

  async verifyAndEnableTwoFactor(
    userId: string,
    token: string,
  ): Promise<boolean> {
    const user = await this.usersService.findByIdWithTwoFactorSecret(userId);

    if (!user.twoFactorSecret) {
      throw new BadRequestException(
        'No 2FA setup found. Please initiate setup first.',
      );
    }

    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (!isValid) {
      throw new UnauthorizedException('Invalid verification code');
    }

    await this.usersService.enableTwoFactor(userId);

    return true;
  }

  // ==========================================
  // LOGIN WITH 2FA - NO CIRCULAR DEPENDENCY
  // ==========================================

  async verify2FALogin(
    email: string,
    token: string,
    tempToken: string,
  ): Promise<any> {
    const userId = await this.verifyTempToken(tempToken);

    const user = await this.usersService.findByEmail(email);
    if (user._id.toString() !== userId) {
      throw new UnauthorizedException('Invalid request');
    }

    const isValid = await this.verifyTwoFactorToken(userId, token);

    if (!isValid) {
      throw new UnauthorizedException('Invalid 2FA code');
    }

    // Generate tokens directly here (no circular dependency)
    return this.complete2FALoginInternal(userId);
  }

  /**
   * Complete 2FA login WITHOUT calling AuthService
   * Generates tokens directly to avoid circular dependency
   */
  private async complete2FALoginInternal(userId: string) {
    const user = await this.usersService.findById(userId);

    await this.usersService.updateLastLogin(userId);

    // Build rich JWT payload
    const payload: JwtPayload = {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
      status: user.status,
      isActive: user.isActive,
      isEmailVerified: user.isEmailVerified,
      twoFactorEnabled: user.twoFactorEnabled,
      firstName: user.firstName,
      lastName: user.lastName,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.jwtSecret,
        expiresIn: this.configService.jwtExpiration,
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.jwtRefreshSecret,
        expiresIn: this.configService.jwtRefreshExpiration,
      }),
    ]);

    await this.usersService.addRefreshToken(userId, refreshToken, '2FA Login');

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

  async verifyTwoFactorToken(userId: string, token: string): Promise<boolean> {
    const user = await this.usersService.findByIdWithTwoFactorSecret(userId);

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      throw new BadRequestException('2FA is not enabled for this account');
    }

    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2,
    });

    return isValid;
  }

  // ==========================================
  // DISABLE 2FA
  // ==========================================

  async disable2FA(
    userId: string,
    email: string,
    password: string,
    token: string,
  ): Promise<boolean> {
    const user = await this.usersService.findByEmail(email);
    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    const isValid = await this.verifyTwoFactorToken(userId, token);

    if (!isValid) {
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.usersService.disableTwoFactor(userId);
    return true;
  }

  // ==========================================
  // BACKUP CODES
  // ==========================================

  async generateBackupCodesWithVerification(
    userId: string,
    email: string,
    password: string,
  ): Promise<{ codes: string[]; message: string }> {
    const user = await this.usersService.findByEmail(email);
    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    if (!user.twoFactorEnabled) {
      throw new BadRequestException('2FA must be enabled first');
    }

    const codes = await this.generateBackupCodes(userId);

    return {
      codes,
      message:
        'Save these backup codes in a secure location. Each code can only be used once.',
    };
  }

  private async generateBackupCodes(userId: string): Promise<string[]> {
    const codes: string[] = [];
    const hashedCodes: string[] = [];

    for (let i = 0; i < 10; i++) {
      const code = this.generateBackupCode();
      codes.push(code);

      const hashedCode = await bcrypt.hash(code, 10);
      hashedCodes.push(hashedCode);
    }

    await this.usersService.updateBackupCodes(userId, hashedCodes);

    return codes;
  }

  async use2FABackupCode(
    email: string,
    backupCode: string,
    tempToken: string,
  ): Promise<any> {
    const userId = await this.verifyTempToken(tempToken);

    const user = await this.usersService.findByEmail(email);
    if (user._id.toString() !== userId) {
      throw new UnauthorizedException('Invalid request');
    }

    await this.verifyBackupCode(userId, backupCode);

    // Generate tokens directly (no circular dependency)
    return this.complete2FALoginInternal(userId);
  }

  private async verifyBackupCode(
    userId: string,
    code: string,
  ): Promise<boolean> {
    const user = await this.usersService.findByIdWithBackupCodes(userId);

    if (!user.twoFactorBackupCodes || user.twoFactorBackupCodes.length === 0) {
      throw new BadRequestException('No backup codes available');
    }

    for (let i = 0; i < user.twoFactorBackupCodes.length; i++) {
      const isMatch = await bcrypt.compare(code, user.twoFactorBackupCodes[i]);

      if (isMatch) {
        await this.usersService.removeBackupCode(userId, i);
        return true;
      }
    }

    throw new UnauthorizedException('Invalid backup code');
  }

  // ==========================================
  // TEMPORARY TOKENS
  // ==========================================

  async generateTempToken(userId: string): Promise<string> {
    return this.jwtService.signAsync(
      {
        sub: userId,
        temp2FA: true,
      },
      {
        secret: this.configService.jwtSecret,
        expiresIn: '5m',
      },
    );
  }

  async verifyTempToken(token: string): Promise<string> {
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.jwtSecret,
      });

      if (!payload.temp2FA) {
        throw new UnauthorizedException('Invalid temporary token');
      }

      return payload.sub;
    } catch (error) {
      throw new UnauthorizedException('Temporary token expired or invalid');
    }
  }

  // ==========================================
  // STATUS & HELPERS
  // ==========================================

  async getTwoFactorStatus(userId: string) {
    const user = await this.usersService.findByIdWithBackupCodes(userId);

    return {
      enabled: user.twoFactorEnabled,
      enabledAt: user.twoFactorEnabledAt,
      hasBackupCodes:
        user.twoFactorBackupCodes && user.twoFactorBackupCodes.length > 0,
      backupCodesRemaining: user.twoFactorBackupCodes?.length || 0,
    };
  }

  private generateBackupCode(): string {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `${code.slice(0, 4)}-${code.slice(4, 8)}`;
  }
}
