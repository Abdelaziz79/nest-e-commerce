// src/mail/mail-queue.controller.ts
import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { MailQueueService } from './mail-queue.service';

@Controller('admin/email-queue')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles('admin', 'super_admin')
export class MailQueueController {
  constructor(private readonly mailQueueService: MailQueueService) {}

  /**
   * Get queue statistics
   * GET /admin/email-queue/stats
   */
  @Get('stats')
  async getStats() {
    return this.mailQueueService.getQueueStats();
  }

  /**
   * Get failed jobs
   * GET /admin/email-queue/failed
   */
  @Get('failed')
  async getFailedJobs() {
    const jobs = await this.mailQueueService.getFailedJobs(50);
    return jobs.map((job) => ({
      id: job.id,
      data: job.data,
      failedReason: job.failedReason,
      attemptsMade: job.attemptsMade,
      timestamp: job.timestamp,
      processedOn: job.processedOn,
      finishedOn: job.finishedOn,
    }));
  }

  /**
   * Retry a specific failed job
   * POST /admin/email-queue/retry/:jobId
   */
  @Post('retry/:jobId')
  @HttpCode(HttpStatus.OK)
  async retryJob(@Param('jobId') jobId: string) {
    await this.mailQueueService.retryJob(jobId);
    return {
      success: true,
      message: `Job ${jobId} queued for retry`,
    };
  }

  /**
   * Retry all failed jobs
   * POST /admin/email-queue/retry-all
   */
  @Post('retry-all')
  @HttpCode(HttpStatus.OK)
  async retryAllFailed() {
    await this.mailQueueService.retryAllFailedJobs();
    return {
      success: true,
      message: 'All failed jobs queued for retry',
    };
  }

  /**
   * Clean old completed/failed jobs
   * DELETE /admin/email-queue/clean
   */
  @Delete('clean')
  @HttpCode(HttpStatus.OK)
  async cleanQueue() {
    await this.mailQueueService.cleanQueue();
    return {
      success: true,
      message: 'Queue cleaned successfully',
    };
  }

  /**
   * Pause queue processing
   * POST /admin/email-queue/pause
   */
  @Post('pause')
  @HttpCode(HttpStatus.OK)
  async pauseQueue() {
    await this.mailQueueService.pauseQueue();
    return {
      success: true,
      message: 'Queue paused',
    };
  }

  /**
   * Resume queue processing
   * POST /admin/email-queue/resume
   */
  @Post('resume')
  @HttpCode(HttpStatus.OK)
  async resumeQueue() {
    await this.mailQueueService.resumeQueue();
    return {
      success: true,
      message: 'Queue resumed',
    };
  }
}
