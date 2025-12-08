// src/mail/mail.service.ts
import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';
import { AppConfigService } from 'src/app.config.service';

export interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
  from?: string;
  replyTo?: string;
  attachments?: Array<{
    filename: string;
    content: Buffer | string;
    contentType?: string;
  }>;
}

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: Transporter | null = null;
  private isConfigured: boolean = false;

  constructor(private readonly configService: AppConfigService) {
    this.initializeGmail();
  }

  private async initializeGmail() {
    const user = this.configService.gmailUser;
    const pass = this.configService.gmailPassword;

    if (!user || !pass) {
      this.logger.warn(
        '⚠️  Gmail credentials not configured. Email functionality will be disabled.',
      );
      this.logger.warn(
        '💡 To enable emails, add GMAIL_USER and GMAIL_APP_PASSWORD to your .env file',
      );
      return;
    }

    try {
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user,
          pass,
        },
        tls: {
          rejectUnauthorized: false,
        },
      });

      await this.transporter.verify();
      this.isConfigured = true;
      this.logger.log('✅ Gmail configured successfully');
      this.logger.log(`📧 Sending emails from: ${user}`);
    } catch (error) {
      this.logger.error('❌ Failed to configure Gmail:', error.message);
      this.logger.error(
        '💡 Make sure you are using an App Password, not your regular Gmail password',
      );
      this.logger.error('💡 Visit: https://myaccount.google.com/apppasswords');
    }
  }

  /**
   * Send a generic email
   */
  async sendEmail(options: EmailOptions): Promise<boolean> {
    if (!this.isConfigured || !this.transporter) {
      this.logger.warn(`Email not sent to ${options.to}: Gmail not configured`);
      return false;
    }

    try {
      const mailOptions = {
        from: `"${this.configService.gmailFromName}" <${this.configService.gmailUser}>`,
        to: options.to,
        replyTo: options.replyTo || this.configService.gmailReplyTo,
        subject: options.subject,
        text: options.text || this.stripHtml(options.html),
        html: options.html,
        attachments: options.attachments,
      };

      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`✅ Email sent successfully to ${options.to}`);
      this.logger.debug(`Message ID: ${info.messageId}`);
      return true;
    } catch (error) {
      this.logger.error(`❌ Failed to send email to ${options.to}:`, error);
      return false;
    }
  }

  // ==========================================
  // ✅ NEW: COMBINED WELCOME + VERIFICATION EMAIL
  // ==========================================

  /**
   * Send welcome email WITH verification code (for email/password registration)
   */
  async sendWelcomeWithVerificationEmail(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<boolean> {
    const subject = `Welcome to ${this.configService.appName}! 🎉`;
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Welcome & Verify Email</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                  <tr>
                    <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                      <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 700;">
                        Welcome to ${this.configService.appName}! 🎉
                      </h1>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="padding: 40px 30px;">
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Hi ${firstName},
                      </p>
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        We're thrilled to have you on board! Your account has been successfully created.
                      </p>
                      
                      <p style="margin: 0 0 30px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        To complete your registration and access all features, please verify your email address using the code below:
                      </p>
                      
                      <!-- OTP Code Box -->
                      <div style="background-color: #f8f9fa; border: 2px dashed #667eea; border-radius: 8px; padding: 30px; text-align: center; margin: 30px 0;">
                        <p style="margin: 0 0 15px 0; font-size: 14px; color: #6c757d; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                          Your Verification Code
                        </p>
                        <div style="font-size: 42px; font-weight: 700; color: #667eea; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                          ${otpCode}
                        </div>
                      </div>

                      <div style="background-color: #FFF3CD; border-left: 4px solid #FFC107; padding: 15px; margin: 20px 0; border-radius: 4px;">
                        <p style="margin: 0; font-size: 14px; color: #856404; font-weight: 600;">
                          ⏰ Important
                        </p>
                        <p style="margin: 10px 0 0 0; font-size: 14px; color: #856404;">
                          This code will expire in <strong>10 minutes</strong>. For security reasons, do not share this code with anyone.
                        </p>
                      </div>

                      <p style="margin: 30px 0 0 0; font-size: 14px; color: #6c757d; line-height: 1.6;">
                        If you didn't create an account, please ignore this email or contact our support team.
                      </p>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-top: 1px solid #e9ecef;">
                      <p style="margin: 0; font-size: 12px; color: #adb5bd;">
                        © ${new Date().getFullYear()} ${this.configService.appName}. All rights reserved.
                      </p>
                      <p style="margin: 10px 0 0 0; font-size: 12px; color: #adb5bd;">
                        This is an automated message, please do not reply.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;

    return this.sendEmail({ to, subject, html });
  }

  /**
   * Send simple welcome email (for social login - Google/GitHub)
   */
  async sendWelcomeEmail(to: string, firstName: string): Promise<boolean> {
    const subject = `Welcome to ${this.configService.appName}! 🎉`;
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Welcome</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                  <tr>
                    <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                      <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 700;">
                        Welcome to ${this.configService.appName}! 🎉
                      </h1>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="padding: 40px 30px;">
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Hi ${firstName},
                      </p>
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        We're thrilled to have you on board! Your account has been successfully created and verified.
                      </p>
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        You're all set to explore everything we have to offer. If you have any questions, feel free to reach out to our support team.
                      </p>
                      
                      <div style="background-color: #E8F5E9; border-left: 4px solid #4CAF50; padding: 15px; margin: 20px 0; border-radius: 4px;">
                        <p style="margin: 0; font-size: 14px; color: #2E7D32; font-weight: 600;">
                          ✅ Account Verified
                        </p>
                        <p style="margin: 10px 0 0 0; font-size: 14px; color: #2E7D32;">
                          Your email has been automatically verified. You can start using your account right away!
                        </p>
                      </div>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-top: 1px solid #e9ecef;">
                      <p style="margin: 0 0 10px 0; font-size: 14px; color: #6c757d;">
                        ${this.configService.appName}
                      </p>
                      <p style="margin: 0; font-size: 12px; color: #adb5bd;">
                        © ${new Date().getFullYear()} All rights reserved.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;

    return this.sendEmail({ to, subject, html });
  }

  // ==========================================
  // OTP EMAIL TEMPLATES (for standalone OTP scenarios)
  // ==========================================

  /**
   * Send Login OTP
   */
  async sendLoginOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<boolean> {
    const subject = 'Your Login Verification Code';
    const html = this.generateOtpTemplate(
      firstName,
      otpCode,
      'Login Verification',
      'Please use the code below to complete your login:',
      '#4F46E5',
    );

    return this.sendEmail({ to, subject, html });
  }

  /**
   * Send Email Verification OTP (standalone - rarely used now)
   */
  async sendEmailVerificationOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<boolean> {
    const subject = 'Verify Your Email Address';
    const html = this.generateOtpTemplate(
      firstName,
      otpCode,
      'Email Verification',
      'Please use the code below to verify your email address:',
      '#10B981',
    );

    return this.sendEmail({ to, subject, html });
  }

  /**
   * Send Password Reset OTP
   */
  async sendPasswordResetOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<boolean> {
    const subject = 'Password Reset Verification Code';
    const html = this.generateOtpTemplate(
      firstName,
      otpCode,
      'Password Reset',
      'Please use the code below to reset your password:',
      '#DC2626',
      'If you did not request a password reset, please ignore this email and your password will remain unchanged.',
    );

    return this.sendEmail({ to, subject, html });
  }

  /**
   * Send Two-Factor Authentication OTP
   */
  async sendTwoFactorOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<boolean> {
    const subject = 'Two-Factor Authentication Code';
    const html = this.generateOtpTemplate(
      firstName,
      otpCode,
      'Two-Factor Authentication',
      'Please use the code below to complete your login:',
      '#8B5CF6',
    );

    return this.sendEmail({ to, subject, html });
  }

  /**
   * Send Account Deletion OTP
   */
  async sendAccountDeletionOtp(
    to: string,
    firstName: string,
    otpCode: string,
  ): Promise<boolean> {
    const subject = 'Account Deletion Confirmation Code';
    const html = this.generateOtpTemplate(
      firstName,
      otpCode,
      'Account Deletion',
      'Please use the code below to confirm account deletion:',
      '#EF4444',
      '⚠️ This action is permanent and cannot be undone. If you did not request this, please contact support immediately.',
    );

    return this.sendEmail({ to, subject, html });
  }

  /**
   * Generic OTP Template Generator
   */
  private generateOtpTemplate(
    firstName: string,
    otpCode: string,
    title: string,
    message: string,
    color: string,
    warningMessage?: string,
  ): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${title}</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                  <tr>
                    <td style="background-color: ${color}; padding: 40px 30px; text-align: center;">
                      <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 700;">
                        ${title}
                      </h1>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="padding: 40px 30px;">
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Hi ${firstName},
                      </p>
                      <p style="margin: 0 0 30px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        ${message}
                      </p>
                      
                      <!-- OTP Code Box -->
                      <div style="background-color: #f8f9fa; border: 2px dashed ${color}; border-radius: 8px; padding: 30px; text-align: center; margin: 30px 0;">
                        <p style="margin: 0 0 15px 0; font-size: 14px; color: #6c757d; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                          Your Verification Code
                        </p>
                        <div style="font-size: 42px; font-weight: 700; color: ${color}; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                          ${otpCode}
                        </div>
                      </div>

                      <div style="background-color: #FFF3CD; border-left: 4px solid #FFC107; padding: 15px; margin: 20px 0; border-radius: 4px;">
                        <p style="margin: 0; font-size: 14px; color: #856404; font-weight: 600;">
                          ⏰ Important
                        </p>
                        <p style="margin: 10px 0 0 0; font-size: 14px; color: #856404;">
                          This code will expire in <strong>10 minutes</strong>. For security reasons, do not share this code with anyone.
                        </p>
                      </div>

                      ${
                        warningMessage
                          ? `
                      <div style="background-color: #FEF2F2; border-left: 4px solid #DC2626; padding: 15px; margin: 20px 0; border-radius: 4px;">
                        <p style="margin: 0; font-size: 14px; color: #991B1B;">
                          ${warningMessage}
                        </p>
                      </div>
                      `
                          : ''
                      }

                      <p style="margin: 30px 0 0 0; font-size: 14px; color: #6c757d; line-height: 1.6;">
                        If you didn't request this code, please ignore this email or contact our support team.
                      </p>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-top: 1px solid #e9ecef;">
                      <p style="margin: 0; font-size: 12px; color: #adb5bd;">
                        © ${new Date().getFullYear()} ${this.configService.appName}. All rights reserved.
                      </p>
                      <p style="margin: 10px 0 0 0; font-size: 12px; color: #adb5bd;">
                        This is an automated message, please do not reply.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;
  }

  // ==========================================
  // OTHER EMAIL TEMPLATES
  // ==========================================

  async sendPasswordChangedEmail(
    to: string,
    firstName: string,
  ): Promise<boolean> {
    const subject = 'Your password has been changed';
    const html = this.generatePasswordChangedTemplate(firstName);
    return this.sendEmail({ to, subject, html });
  }

  async sendAccountLockedEmail(
    to: string,
    firstName: string,
    unlockTime: Date,
  ): Promise<boolean> {
    const subject = 'Account temporarily locked';
    const html = this.generateAccountLockedTemplate(firstName, unlockTime);
    return this.sendEmail({ to, subject, html });
  }

  async sendOrderConfirmationEmail(
    to: string,
    firstName: string,
    orderDetails: any,
  ): Promise<boolean> {
    const subject = `Order Confirmation #${orderDetails.orderId}`;
    const html = this.generateOrderConfirmationTemplate(
      firstName,
      orderDetails,
    );
    return this.sendEmail({ to, subject, html });
  }

  private generatePasswordChangedTemplate(firstName: string): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Password Changed</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                  <tr>
                    <td style="background-color: #10B981; padding: 40px 30px; text-align: center;">
                      <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 700;">
                        ✓ Password Changed
                      </h1>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="padding: 40px 30px;">
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Hi ${firstName},
                      </p>
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        This is a confirmation that your password has been successfully changed.
                      </p>
                      <div style="background-color: #ECFDF5; border-left: 4px solid #10B981; padding: 15px; margin: 20px 0;">
                        <p style="margin: 0; font-size: 14px; color: #065F46;">
                          If you did not make this change, please contact our support team immediately.
                        </p>
                      </div>
                      <p style="margin: 20px 0 0 0; font-size: 16px; color: #333; line-height: 1.6;">
                        For security reasons, you have been logged out of all devices. Please log in again with your new password.
                      </p>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-top: 1px solid #e9ecef;">
                      <p style="margin: 0; font-size: 12px; color: #adb5bd;">
                        © ${new Date().getFullYear()} ${this.configService.appName}. All rights reserved.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;
  }

  private generateAccountLockedTemplate(
    firstName: string,
    unlockTime: Date,
  ): string {
    const formattedTime = unlockTime.toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    });

    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Account Locked</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                  <tr>
                    <td style="background-color: #F59E0B; padding: 40px 30px; text-align: center;">
                      <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 700;">
                        Account Temporarily Locked
                      </h1>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="padding: 40px 30px;">
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Hi ${firstName},
                      </p>
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Your account has been temporarily locked due to multiple failed login attempts.
                      </p>
                      <div style="background-color: #FFFBEB; border-left: 4px solid #F59E0B; padding: 15px; margin: 20px 0;">
                        <p style="margin: 0; font-size: 14px; color: #92400E; font-weight: 600;">
                          Your account will be automatically unlocked at:
                        </p>
                        <p style="margin: 10px 0 0 0; font-size: 16px; color: #92400E; font-weight: 700;">
                          ${formattedTime}
                        </p>
                      </div>
                      <p style="margin: 20px 0 0 0; font-size: 16px; color: #333; line-height: 1.6;">
                        If you believe this was a mistake or if you didn't attempt to log in, please contact our support team immediately.
                      </p>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-top: 1px solid #e9ecef;">
                      <p style="margin: 0; font-size: 12px; color: #adb5bd;">
                        © ${new Date().getFullYear()} ${this.configService.appName}. All rights reserved.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;
  }

  private generateOrderConfirmationTemplate(
    firstName: string,
    orderDetails: any,
  ): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Order Confirmation</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                  <tr>
                    <td style="background-color: #10B981; padding: 40px 30px; text-align: center;">
                      <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 700;">
                        Order Confirmed! 🎉
                      </h1>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="padding: 40px 30px;">
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Hi ${firstName},
                      </p>
                      <p style="margin: 0 0 20px 0; font-size: 16px; color: #333; line-height: 1.6;">
                        Thank you for your order! We've received it and will process it shortly.
                      </p>
                      <div style="background-color: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0;">
                        <p style="margin: 0 0 10px 0; font-size: 14px; color: #6c757d;">Order Number:</p>
                        <p style="margin: 0; font-size: 20px; color: #333; font-weight: 700;">#${orderDetails.orderId}</p>
                      </div>
                      <p style="margin: 20px 0 0 0; font-size: 16px; color: #333; line-height: 1.6;">
                        We'll send you another email when your order ships.
                      </p>
                    </td>
                  </tr>
                  
                  <tr>
                    <td style="background-color: #f8f9fa; padding: 30px; text-align: center; border-top: 1px solid #e9ecef;">
                      <p style="margin: 0; font-size: 12px; color: #adb5bd;">
                        © ${new Date().getFullYear()} ${this.configService.appName}. All rights reserved.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
      </html>
    `;
  }

  /**
   * Utility: Strip HTML tags for plain text version
   */
  private stripHtml(html: string): string {
    return html
      .replace(/<style[^>]*>.*<\/style>/gm, '')
      .replace(/<script[^>]*>.*<\/script>/gm, '')
      .replace(/<[^>]+>/gm, '')
      .replace(/\s+/g, ' ')
      .trim();
  }
}
