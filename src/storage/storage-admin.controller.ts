// src/storage/storage-admin.controller.ts
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
import { Roles } from '../auth/decorators/roles.decorator';
import { RolesGuard } from '../auth/guards/roles.guard';
import { StorageQueueService } from './storage-queue.service';
import { StorageService } from './storage.service';

@Controller('admin/storage-queue')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles('admin', 'super_admin')
export class StorageAdminController {
  constructor(private readonly storageQueueService: StorageQueueService) {}

  /**
   * Get queue statistics
   * GET /admin/storage-queue/stats
   */
  @Get('stats')
  async getStats() {
    return this.storageQueueService.getQueueStats();
  }

  /**
   * Get failed jobs
   * GET /admin/storage-queue/failed
   */
  @Get('failed')
  async getFailedJobs() {
    const jobs = await this.storageQueueService.getFailedJobs(50);
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
   * POST /admin/storage-queue/retry/:jobId
   */
  @Post('retry/:jobId')
  @HttpCode(HttpStatus.OK)
  async retryJob(@Param('jobId') jobId: string) {
    await this.storageQueueService.retryJob(jobId);
    return {
      success: true,
      message: `Job ${jobId} queued for retry`,
    };
  }

  /**
   * Retry all failed jobs
   * POST /admin/storage-queue/retry-all
   */
  @Post('retry-all')
  @HttpCode(HttpStatus.OK)
  async retryAllFailed() {
    await this.storageQueueService.retryAllFailedJobs();
    return {
      success: true,
      message: 'All failed jobs queued for retry',
    };
  }

  /**
   * Clean old completed/failed jobs
   * DELETE /admin/storage-queue/clean
   */
  @Delete('clean')
  @HttpCode(HttpStatus.OK)
  async cleanQueue() {
    await this.storageQueueService.cleanQueue();
    return {
      success: true,
      message: 'Queue cleaned successfully',
    };
  }

  /**
   * Pause queue processing
   * POST /admin/storage-queue/pause
   */
  @Post('pause')
  @HttpCode(HttpStatus.OK)
  async pauseQueue() {
    await this.storageQueueService.pauseQueue();
    return {
      success: true,
      message: 'Queue paused',
    };
  }

  /**
   * Resume queue processing
   * POST /admin/storage-queue/resume
   */
  @Post('resume')
  @HttpCode(HttpStatus.OK)
  async resumeQueue() {
    await this.storageQueueService.resumeQueue();
    return {
      success: true,
      message: 'Queue resumed',
    };
  }

  /**
   * Trigger cleanup of expired files
   * POST /admin/storage-queue/cleanup-expired
   */
  @Post('cleanup-expired')
  @HttpCode(HttpStatus.OK)
  async cleanupExpired() {
    await this.storageQueueService.cleanupExpiredFiles();
    return {
      success: true,
      message: 'Cleanup job queued',
    };
  }
}
