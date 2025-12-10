// src/storage/storage-queue.service.ts
import { InjectQueue } from '@nestjs/bull';
import { Injectable, Logger } from '@nestjs/common';
import type { Queue } from 'bull';
import { FileTypeEnum } from './schemas/file.schema';

export enum FileJobPriority {
  CRITICAL = 1, // Avatar uploads (user waiting)
  HIGH = 2, // Product images (admin/vendor)
  NORMAL = 3, // Thumbnails, variants
  LOW = 4, // Cleanup, optimization
}

export enum FileJobType {
  OPTIMIZE_IMAGE = 'optimize_image',
  GENERATE_VARIANTS = 'generate_variants',
  EXTRACT_METADATA = 'extract_metadata',
  DELETE_FILE = 'delete_file',
  CLEANUP_EXPIRED = 'cleanup_expired',
  PROCESS_UPLOAD = 'process_upload',
}

export interface FileJobData {
  type: FileJobType;
  fileId: string;
  data?: any;
}

@Injectable()
export class StorageQueueService {
  private readonly logger = new Logger(StorageQueueService.name);

  constructor(
    @InjectQueue('file-processing')
    private readonly fileQueue: Queue<FileJobData>,
  ) {}

  /**
   * Add job to queue with proper configuration
   */
  private async addToQueue(
    jobData: FileJobData,
    priority: FileJobPriority = FileJobPriority.NORMAL,
    delay?: number,
  ): Promise<void> {
    try {
      const job = await this.fileQueue.add(jobData, {
        priority,
        delay,
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000,
        },
        removeOnComplete: {
          age: 3600, // Keep for 1 hour
          count: 100,
        },
        removeOnFail: {
          age: 86400, // Keep for 24 hours
          count: 500,
        },
      });

      this.logger.debug(
        `File job added: ${job.id} - Type: ${jobData.type} - Priority: ${priority}`,
      );
    } catch (error) {
      this.logger.error(`Failed to add file job to queue:`, error);
      throw error;
    }
  }

  // ==========================================
  // IMAGE PROCESSING JOBS
  // ==========================================

  async processUpload(fileId: string, fileType: FileTypeEnum): Promise<void> {
    const priority =
      fileType === FileTypeEnum.AVATAR
        ? FileJobPriority.CRITICAL
        : FileJobPriority.HIGH;

    await this.addToQueue(
      {
        type: FileJobType.PROCESS_UPLOAD,
        fileId,
        data: { fileType },
      },
      priority,
    );
  }

  async optimizeImage(fileId: string): Promise<void> {
    await this.addToQueue(
      {
        type: FileJobType.OPTIMIZE_IMAGE,
        fileId,
      },
      FileJobPriority.HIGH,
    );
  }

  async generateVariants(
    fileId: string,
    fileType: FileTypeEnum,
  ): Promise<void> {
    await this.addToQueue(
      {
        type: FileJobType.GENERATE_VARIANTS,
        fileId,
        data: { fileType },
      },
      FileJobPriority.NORMAL,
    );
  }

  async extractMetadata(fileId: string): Promise<void> {
    await this.addToQueue(
      {
        type: FileJobType.EXTRACT_METADATA,
        fileId,
      },
      FileJobPriority.NORMAL,
    );
  }

  // ==========================================
  // FILE MANAGEMENT JOBS
  // ==========================================

  async deleteFile(fileId: string): Promise<void> {
    await this.addToQueue(
      {
        type: FileJobType.DELETE_FILE,
        fileId,
      },
      FileJobPriority.NORMAL,
    );
  }

  async cleanupExpiredFiles(): Promise<void> {
    await this.addToQueue(
      {
        type: FileJobType.CLEANUP_EXPIRED,
        fileId: 'system',
      },
      FileJobPriority.LOW,
    );
  }

  // ==========================================
  // QUEUE MANAGEMENT
  // ==========================================

  async getQueueStats() {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.fileQueue.getWaitingCount(),
      this.fileQueue.getActiveCount(),
      this.fileQueue.getCompletedCount(),
      this.fileQueue.getFailedCount(),
      this.fileQueue.getDelayedCount(),
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
    await this.fileQueue.clean(grace, 'completed');
    await this.fileQueue.clean(grace, 'failed');
    this.logger.log(`Queue cleaned: removed jobs older than ${grace}ms`);
  }

  async pauseQueue(): Promise<void> {
    await this.fileQueue.pause();
    this.logger.warn('File processing queue paused');
  }

  async resumeQueue(): Promise<void> {
    await this.fileQueue.resume();
    this.logger.log('File processing queue resumed');
  }

  async getFailedJobs(count: number = 10) {
    return this.fileQueue.getFailed(0, count);
  }

  async retryJob(jobId: string): Promise<void> {
    const job = await this.fileQueue.getJob(jobId);
    if (job) {
      await job.retry();
      this.logger.log(`Job ${jobId} queued for retry`);
    }
  }

  async retryAllFailedJobs(): Promise<void> {
    const failedJobs = await this.fileQueue.getFailed();
    for (const job of failedJobs) {
      await job.retry();
    }
    this.logger.log(`${failedJobs.length} failed jobs queued for retry`);
  }
}
