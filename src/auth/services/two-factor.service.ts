import {
  BadRequestException,
  forwardRef,
  Inject,
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
import { AuthService } from '../auth.service';

@Injectable()
export class TwoFactorService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: AppConfigService,
    private readonly usersService: UsersService,
    @Inject(forwardRef(() => AuthService))
    private readonly authService: AuthService,
  ) {}

  // ==========================================
  // SETUP 2FA
  // ==========================================

  /**
   * Initiate 2FA setup (with password verification)
   */
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
    // Verify password before initiating setup
    const user = await this.usersService.findByEmail(email);
    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // Generate 2FA secret and QR code
    return this.generateTwoFactorSecret(userId);
  }

  /**
   * Generate 2FA secret and QR code for setup
   */
  private async generateTwoFactorSecret(userId: string) {
    const user = await this.usersService.findById(userId);

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${this.configService.appName} (${user.email})`,
      issuer: this.configService.appName,
      length: 32,
    });

    // Generate QR code
    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

    // Store secret temporarily (not enabled yet until verified)
    await this.usersService.updateTwoFactorSecret(userId, secret.base32);

    return {
      secret: secret.base32,
      qrCode: qrCodeDataUrl,
      manualEntryKey: secret.base32,
      message:
        'Scan the QR code with your authenticator app and verify with a code to enable 2FA',
    };
  }

  /**
   * Verify 2FA setup token and enable 2FA
   */
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

    // Verify the token
    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2, // Allow 2 time steps before/after (60 seconds)
    });

    if (!isValid) {
      throw new UnauthorizedException('Invalid verification code');
    }

    // Enable 2FA
    await this.usersService.enableTwoFactor(userId);

    return true;
  }

  // ==========================================
  // LOGIN WITH 2FA
  // ==========================================

  /**
   * Verify 2FA token during login (complete flow)
   */
  async verify2FALogin(
    email: string,
    token: string,
    tempToken: string,
  ): Promise<any> {
    // Verify temporary token
    const userId = await this.verifyTempToken(tempToken);

    // Verify user email matches
    const user = await this.usersService.findByEmail(email);
    if (user._id.toString() !== userId) {
      throw new UnauthorizedException('Invalid request');
    }

    // Verify 2FA token
    const isValid = await this.verifyTwoFactorToken(userId, token);

    if (!isValid) {
      throw new UnauthorizedException('Invalid 2FA code');
    }

    // Complete login and generate tokens
    return this.authService.complete2FALogin(userId);
  }

  /**
   * Verify 2FA token during login
   */
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

  /**
   * Disable 2FA (requires password and 2FA token)
   */
  async disable2FA(
    userId: string,
    email: string,
    password: string,
    token: string,
  ): Promise<boolean> {
    // Verify password
    const user = await this.usersService.findByEmail(email);
    const isPasswordValid = await user.validatePassword(password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // Verify 2FA token
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

  /**
   * Generate backup codes with password verification
   */
  async generateBackupCodesWithVerification(
    userId: string,
    email: string,
    password: string,
  ): Promise<{ codes: string[]; message: string }> {
    // Verify password
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

  /**
   * Generate backup codes
   */
  private async generateBackupCodes(userId: string): Promise<string[]> {
    const codes: string[] = [];
    const hashedCodes: string[] = [];

    // Generate 10 backup codes
    for (let i = 0; i < 10; i++) {
      const code = this.generateBackupCode();
      codes.push(code);

      // Hash the code before storing
      const hashedCode = await bcrypt.hash(code, 10);
      hashedCodes.push(hashedCode);
    }

    // Store hashed codes
    await this.usersService.updateBackupCodes(userId, hashedCodes);

    return codes;
  }

  /**
   * Use backup code for login
   */
  async use2FABackupCode(
    email: string,
    backupCode: string,
    tempToken: string,
  ): Promise<any> {
    // Verify temporary token
    const userId = await this.verifyTempToken(tempToken);

    // Verify user email matches
    const user = await this.usersService.findByEmail(email);
    if (user._id.toString() !== userId) {
      throw new UnauthorizedException('Invalid request');
    }

    // Verify backup code
    await this.verifyBackupCode(userId, backupCode);

    // Complete login and generate tokens
    return this.authService.complete2FALogin(userId);
  }

  /**
   * Verify backup code
   */
  private async verifyBackupCode(
    userId: string,
    code: string,
  ): Promise<boolean> {
    const user = await this.usersService.findByIdWithBackupCodes(userId);

    if (!user.twoFactorBackupCodes || user.twoFactorBackupCodes.length === 0) {
      throw new BadRequestException('No backup codes available');
    }

    // Try to match against stored hashed codes
    for (let i = 0; i < user.twoFactorBackupCodes.length; i++) {
      const isMatch = await bcrypt.compare(code, user.twoFactorBackupCodes[i]);

      if (isMatch) {
        // Remove used backup code
        await this.usersService.removeBackupCode(userId, i);
        return true;
      }
    }

    throw new UnauthorizedException('Invalid backup code');
  }

  // ==========================================
  // TEMPORARY TOKENS
  // ==========================================

  /**
   * Generate temporary token for 2FA flow
   */
  async generateTempToken(userId: string): Promise<string> {
    return this.jwtService.signAsync(
      {
        sub: userId,
        temp2FA: true,
      },
      {
        secret: this.configService.jwtSecret,
        expiresIn: '5m', // 5 minutes to complete 2FA
      },
    );
  }

  /**
   * Verify temporary token
   */
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

  /**
   * Get 2FA status for user
   */
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

  /**
   * Generate a random backup code
   */
  private generateBackupCode(): string {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `${code.slice(0, 4)}-${code.slice(4, 8)}`;
  }
}
