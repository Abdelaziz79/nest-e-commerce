// src/mail/processors/email.processor.ts
import {
  OnQueueActive,
  OnQueueCompleted,
  OnQueueFailed,
  Process,
  Processor,
} from '@nestjs/bull';
import { Logger } from '@nestjs/common';
import type { Job } from 'bull';
import { EmailJobData, EmailJobType } from '../mail-queue.service';
import { MailService } from '../mail.service';

@Processor('email')
export class EmailProcessor {
  private readonly logger = new Logger(EmailProcessor.name);

  constructor(private readonly mailService: MailService) {}

  /**
   * Main email processing handler
   * This is the ONLY @Process() decorator - handles all jobs
   */
  @Process()
  async handleEmailJob(job: Job<EmailJobData>): Promise<void> {
    const { type, to, data } = job.data;

    this.logger.debug(
      `Processing email job ${job.id}: ${type} to ${to} (Attempt ${job.attemptsMade + 1}/${job.opts.attempts})`,
    );

    try {
      let success = false;

      switch (type) {
        case EmailJobType.WELCOME_WITH_VERIFICATION:
          success = await this.mailService.sendWelcomeWithVerificationEmail(
            to,
            data.firstName,
            data.otpCode,
          );
          break;

        case EmailJobType.WELCOME:
          success = await this.mailService.sendWelcomeEmail(to, data.firstName);
          break;

        case EmailJobType.EMAIL_VERIFICATION:
          success = await this.mailService.sendEmailVerificationOtp(
            to,
            data.firstName,
            data.otpCode,
          );
          break;

        case EmailJobType.PASSWORD_RESET:
          success = await this.mailService.sendPasswordResetOtp(
            to,
            data.firstName,
            data.otpCode,
          );
          break;

        case EmailJobType.PASSWORD_CHANGED:
          success = await this.mailService.sendPasswordChangedEmail(
            to,
            data.firstName,
          );
          break;

        case EmailJobType.ACCOUNT_LOCKED:
          success = await this.mailService.sendAccountLockedEmail(
            to,
            data.firstName,
            data.unlockTime,
          );
          break;

        case EmailJobType.TWO_FACTOR:
          success = await this.mailService.sendTwoFactorOtp(
            to,
            data.firstName,
            data.otpCode,
          );
          break;

        case EmailJobType.ACCOUNT_DELETION:
          success = await this.mailService.sendAccountDeletionOtp(
            to,
            data.firstName,
            data.otpCode,
          );
          break;

        case EmailJobType.ORDER_CONFIRMATION:
          success = await this.mailService.sendOrderConfirmationEmail(
            to,
            data.firstName,
            data.orderDetails,
          );
          break;

        case EmailJobType.GENERIC:
          success = await this.mailService.sendEmail({
            to,
            subject: data.subject,
            html: data.html,
          });
          break;

        default:
          this.logger.error(`Unknown email job type: ${type}`);
          throw new Error(`Unknown email job type: ${type}`);
      }

      if (!success) {
        throw new Error('Email sending returned false');
      }

      this.logger.log(`✅ Email job ${job.id} completed successfully`);
    } catch (error) {
      this.logger.error(
        `❌ Email job ${job.id} failed (Attempt ${job.attemptsMade + 1}):`,
        error.message,
      );

      // If this was the last attempt, log it as a critical failure
      if (job.opts.attempts && job.attemptsMade >= job.opts.attempts - 1) {
        this.logger.error(
          `🚨 Email job ${job.id} permanently failed after ${job.opts.attempts} attempts`,
        );
        this.logger.error(`Failed email details:`, {
          type,
          to,
          jobId: job.id,
          error: error.message,
        });
      }

      throw error; // Re-throw to trigger Bull's retry mechanism
    }
  }

  /**
   * Event handler: Called when a job becomes active
   */
  @OnQueueActive()
  onActive(job: Job<EmailJobData>) {
    this.logger.debug(`Processing job ${job.id} of type ${job.data.type}`);
  }

  /**
   * Event handler: Called when a job completes successfully
   */
  @OnQueueCompleted()
  onCompleted(job: Job<EmailJobData>) {
    this.logger.debug(`Job ${job.id} completed successfully`);
  }

  /**
   * Event handler: Called when a job fails permanently
   */
  @OnQueueFailed()
  onFailed(job: Job<EmailJobData>, error: Error) {
    this.logger.error(
      `Job ${job.id} failed permanently after ${job.attemptsMade} attempts:`,
      error.message,
    );
  }
}
