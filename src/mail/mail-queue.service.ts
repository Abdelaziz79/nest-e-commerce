// src/mail/mail-queue.service.ts

import { InjectQueue } from '@nestjs/bull';
import { Injectable, Logger } from '@nestjs/common';
import type { Queue } from 'bull';

export enum EmailPriority {
  CRITICAL = 1, // Password resets, security alerts
  HIGH = 2, // Email verification, 2FA
  NORMAL = 3, // Welcome emails, general notifications
  LOW = 4, // Marketing, newsletters
}

export enum EmailJobType {
  WELCOME_WITH_VERIFICATION = 'welcome_with_verification',
  WELCOME = 'welcome',
  EMAIL_VERIFICATION = 'email_verification',
  PASSWORD_RESET = 'password_reset',
  PASSWORD_CHANGED = 'password_changed',
  ACCOUNT_LOCKED = 'account_locked',
  TWO_FACTOR = 'two_factor',
  ACCOUNT_DELETION = 'account_deletion',
  ORDER_CONFIRMATION = 'order_confirmation',
  GENERIC = 'generic',
}

export interface EmailJobData {
  type: EmailJobType;
  to: string;
  data: any;
}

@Injectable()
export class MailQueueService {
  private readonly logger = new Logger(MailQueueService.name);

  constructor(
    @InjectQueue('email') private readonly emailQueue: Queue<EmailJobData>,
  ) {}

  /**
   * Keep completed jobs for 1 hour so they appear in Bull Board
   */
  private async addToQueue(
    jobData: EmailJobData,
    priority: EmailPriority = EmailPriority.NORMAL,
    delay?: number,
  ): Promise<void> {
    try {
      const job = await this.emailQueue.add(jobData, {
        priority,
        delay,
        // FIX: Keep completed jobs for 1 hour (3600 seconds)
        removeOnComplete: {
          age: 3600, // Keep for 1 hour
          count: 100, // Keep last 100
        },
        // Keep failed jobs for debugging
        removeOnFail: {
          age: 86400, // Keep for 24 hours
          count: 500, // Keep last 500
        },
      });

      this.logger.debug(
        `Email job added to queue: ${job.id} - Type: ${jobData.type} - Priority: ${priority}`,
      );
    } catch (error) {
      this.logger.error(`Failed to add email to queue:`, error);
      throw error;
    }
  }

  // ==========================================
  // WELCOME EMAILS
  // ==========================================

  async sendWelcomeWithVerification(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.WELCOME_WITH_VERIFICATION,
        to,
        data: { firstName, otpCode },
      },
      EmailPriority.HIGH,
    );
  }

  async sendWelcomeEmail(to: string, firstName: string): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.WELCOME,
        to,
        data: { firstName },
      },
      EmailPriority.NORMAL,
    );
  }

  // ==========================================
  // OTP EMAILS
  // ==========================================

  async sendEmailVerificationOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.EMAIL_VERIFICATION,
        to,
        data: { firstName, otpCode },
      },
      EmailPriority.HIGH,
    );
  }

  async sendPasswordResetOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.PASSWORD_RESET,
        to,
        data: { firstName, otpCode },
      },
      EmailPriority.CRITICAL,
    );
  }

  async sendTwoFactorOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.TWO_FACTOR,
        to,
        data: { firstName, otpCode },
      },
      EmailPriority.CRITICAL,
    );
  }

  async sendAccountDeletionOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.ACCOUNT_DELETION,
        to,
        data: { firstName, otpCode },
      },
      EmailPriority.HIGH,
    );
  }

  // ==========================================
  // NOTIFICATION EMAILS
  // ==========================================

  async sendPasswordChangedEmail(to: string, firstName: string): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.PASSWORD_CHANGED,
        to,
        data: { firstName },
      },
      EmailPriority.CRITICAL,
    );
  }

  async sendAccountLockedEmail(
    to: string,
    firstName: string,
    unlockTime: Date,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.ACCOUNT_LOCKED,
        to,
        data: { firstName, unlockTime },
      },
      EmailPriority.HIGH,
    );
  }

  async sendOrderConfirmationEmail(
    to: string,
    firstName: string,
    orderDetails: any,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.ORDER_CONFIRMATION,
        to,
        data: { firstName, orderDetails },
      },
      EmailPriority.NORMAL,
    );
  }

  // ==========================================
  // GENERIC EMAIL
  // ==========================================

  async sendGenericEmail(
    to: string,
    subject: string,
    html: string,
    priority: EmailPriority = EmailPriority.NORMAL,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: EmailJobType.GENERIC,
        to,
        data: { subject, html },
      },
      priority,
    );
  }

  // ==========================================
  // QUEUE MANAGEMENT
  // ==========================================

  async getQueueStats() {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.emailQueue.getWaitingCount(),
      this.emailQueue.getActiveCount(),
      this.emailQueue.getCompletedCount(),
      this.emailQueue.getFailedCount(),
      this.emailQueue.getDelayedCount(),
    ]);

    return {
      waiting,
      active,
      completed,
      failed,
      delayed,
      total: waiting + active + completed + failed + delayed,
    };
  }

  async cleanQueue(grace: number = 24 * 60 * 60 * 1000): Promise<void> {
    await this.emailQueue.clean(grace, 'completed');
    await this.emailQueue.clean(grace, 'failed');
    this.logger.log(`Queue cleaned: removed jobs older than ${grace}ms`);
  }

  async pauseQueue(): Promise<void> {
    await this.emailQueue.pause();
    this.logger.warn('Email queue paused');
  }

  async resumeQueue(): Promise<void> {
    await this.emailQueue.resume();
    this.logger.log('Email queue resumed');
  }

  async getFailedJobs(count: number = 10) {
    return this.emailQueue.getFailed(0, count);
  }

  async retryJob(jobId: string): Promise<void> {
    const job = await this.emailQueue.getJob(jobId);
    if (job) {
      await job.retry();
      this.logger.log(`Job ${jobId} queued for retry`);
    }
  }

  async retryAllFailedJobs(): Promise<void> {
    const failedJobs = await this.emailQueue.getFailed();
    for (const job of failedJobs) {
      await job.retry();
    }
    this.logger.log(`${failedJobs.length} failed jobs queued for retry`);
  }
}
