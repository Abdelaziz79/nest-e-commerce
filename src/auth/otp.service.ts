// src/auth/otp.service.ts - FIXED VERSION

import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { Model } from 'mongoose';
import { MailQueueService } from 'src/mail/mail-queue.service';
import { Otp, OtpType } from './schemas/otp.schema';

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);
  private readonly OTP_LENGTH = 6;
  private readonly OTP_EXPIRY_MINUTES = 10;
  private readonly MAX_ATTEMPTS = 5;

  constructor(
    @InjectModel(Otp.name) private readonly otpModel: Model<Otp>,
    private readonly mailQueueService: MailQueueService,
  ) {}

  /**
   * Generate a random 6-digit OTP
   */
  generateOtpCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  /**
   * ✅ NEW: Generate OTP and store in DB WITHOUT sending email
   * This allows the caller to decide when/how to send the email
   */
  async generateOtp(
    email: string,
    type: OtpType,
    metadata?: { ipAddress?: string; userAgent?: string; userId?: string },
  ): Promise<string> {
    try {
      // Delete any existing unused OTPs for this email/type
      await this.otpModel.deleteMany({
        email: email.toLowerCase(),
        type,
        isUsed: false,
      });

      const otpCode = this.generateOtpCode();
      const hashedOtp = await bcrypt.hash(otpCode, 10);

      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + this.OTP_EXPIRY_MINUTES);

      await this.otpModel.create({
        email: email.toLowerCase(),
        code: hashedOtp,
        type,
        expiresAt,
        userId: metadata?.userId,
        ipAddress: metadata?.ipAddress,
        userAgent: metadata?.userAgent,
      });

      this.logger.log(`OTP generated for ${email} (type: ${type})`);
      return otpCode;
    } catch (error) {
      this.logger.error(`Failed to generate OTP for ${email}:`, error);
      throw new BadRequestException('Failed to generate OTP');
    }
  }

  /**
   * ✅ DEPRECATED: Old method that generates AND sends email
   * Keep for backward compatibility with password reset flow
   */
  async generateAndSendOtp(
    email: string,
    type: OtpType,
    firstName?: string,
    metadata?: { ipAddress?: string; userAgent?: string; userId?: string },
  ): Promise<string> {
    const otpCode = await this.generateOtp(email, type, metadata);
    await this.sendOtpEmail(email, otpCode, type, firstName);
    this.logger.log(`OTP generated and queued for ${email} (type: ${type})`);
    return otpCode;
  }

  /**
   * Send OTP email based on type
   */
  private async sendOtpEmail(
    email: string,
    otpCode: string,
    type: OtpType,
    firstName?: string,
  ): Promise<void> {
    const name = firstName || 'User';

    switch (type) {
      case OtpType.EMAIL_VERIFICATION:
        await this.mailQueueService.sendEmailVerificationOtp(
          email,
          name,
          otpCode,
        );
        break;

      case OtpType.PASSWORD_RESET:
        await this.mailQueueService.sendPasswordResetOtp(email, name, otpCode);
        break;

      case OtpType.TWO_FACTOR:
        await this.mailQueueService.sendTwoFactorOtp(email, name, otpCode);
        break;

      case OtpType.ACCOUNT_DELETION:
        await this.mailQueueService.sendAccountDeletionOtp(
          email,
          name,
          otpCode,
        );
        break;
    }
  }

  /**
   * Verify OTP
   */
  async verifyOtp(
    email: string,
    otpCode: string,
    type: OtpType,
  ): Promise<boolean> {
    const normalizedEmail = email.toLowerCase();

    const otpRecords = await this.otpModel
      .find({
        email: normalizedEmail,
        type,
        isUsed: false,
        expiresAt: { $gt: new Date() },
      })
      .sort({ createdAt: -1 });

    if (otpRecords.length === 0) {
      this.logger.warn(
        `No valid OTP found for ${normalizedEmail} (type: ${type})`,
      );
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    for (const otpRecord of otpRecords) {
      if (otpRecord.attempts >= this.MAX_ATTEMPTS) {
        await this.otpModel.deleteOne({ _id: otpRecord._id });
        throw new UnauthorizedException(
          'Maximum verification attempts exceeded. Please request a new OTP.',
        );
      }

      const isValid = await bcrypt.compare(otpCode, otpRecord.code);

      if (isValid) {
        await this.otpModel.updateOne({ _id: otpRecord._id }, { isUsed: true });
        await this.otpModel.deleteMany({
          email: normalizedEmail,
          type,
          isUsed: false,
          _id: { $ne: otpRecord._id },
        });

        this.logger.log(
          `OTP verified successfully for ${normalizedEmail} (type: ${type})`,
        );
        return true;
      } else {
        await this.otpModel.updateOne(
          { _id: otpRecord._id },
          { $inc: { attempts: 1 } },
        );
      }
    }

    throw new UnauthorizedException('Invalid OTP');
  }

  /**
   * Check if OTP is required for this email and type
   */
  async hasValidOtp(email: string, type: OtpType): Promise<boolean> {
    const count = await this.otpModel.countDocuments({
      email: email.toLowerCase(),
      type,
      isUsed: false,
      expiresAt: { $gt: new Date() },
    });

    return count > 0;
  }

  /**
   * Delete all OTPs for an email and type
   */
  async deleteOtps(email: string, type: OtpType): Promise<void> {
    await this.otpModel.deleteMany({ email: email.toLowerCase(), type });
  }

  /**
   * Clean up expired OTPs (can be called by a cron job)
   */
  async cleanupExpiredOtps(): Promise<number> {
    const result = await this.otpModel.deleteMany({
      expiresAt: { $lt: new Date() },
    });

    this.logger.log(`Cleaned up ${result.deletedCount} expired OTPs`);
    return result.deletedCount;
  }

  /**
   * Resend OTP (with rate limiting check)
   */
  async resendOtp(
    email: string,
    type: OtpType,
    firstName?: string,
    metadata?: { ipAddress?: string; userAgent?: string; userId?: string },
  ): Promise<string> {
    const normalizedEmail = email.toLowerCase();

    // Check if there's a recent OTP (within last 1 minute)
    const recentOtp = await this.otpModel.findOne({
      email: normalizedEmail,
      type,
      createdAt: { $gt: new Date(Date.now() - 60000) },
    });

    if (recentOtp) {
      this.logger.warn(
        `Rate limit hit for resend OTP: ${normalizedEmail} (type: ${type})`,
      );
      throw new BadRequestException(
        'Please wait at least 1 minute before requesting a new OTP',
      );
    }

    return this.generateAndSendOtp(email, type, firstName, metadata);
  }
}
