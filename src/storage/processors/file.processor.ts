// src/storage/processors/file.processor.ts
import {
  OnQueueActive,
  OnQueueCompleted,
  OnQueueFailed,
  Process,
  Processor,
} from '@nestjs/bull';
import { Logger } from '@nestjs/common';
import type { Job } from 'bull';
import { FileJobData, FileJobType } from '../storage-queue.service';
import { StorageService } from '../storage.service';

@Processor('file-processing')
export class FileProcessor {
  private readonly logger = new Logger(FileProcessor.name);

  constructor(private readonly storageService: StorageService) {}

  /**
   * Main file processing handler
   */
  @Process()
  async handleFileJob(job: Job<FileJobData>): Promise<void> {
    const { type, fileId, data } = job.data;

    this.logger.debug(
      `Processing file job ${job.id}: ${type} for file ${fileId} (Attempt ${job.attemptsMade + 1}/${job.opts.attempts})`,
    );

    try {
      let success = false;

      switch (type) {
        case FileJobType.PROCESS_UPLOAD:
          success = await this.storageService.processUploadedFile(
            fileId,
            data?.fileType,
          );
          break;

        case FileJobType.OPTIMIZE_IMAGE:
          success = await this.storageService.optimizeImage(fileId);
          break;

        case FileJobType.GENERATE_VARIANTS:
          success = await this.storageService.generateImageVariants(
            fileId,
            data?.fileType,
          );
          break;

        case FileJobType.EXTRACT_METADATA:
          success = await this.storageService.extractFileMetadata(fileId);
          break;

        case FileJobType.DELETE_FILE:
          success = await this.storageService.deleteFileFromDisk(fileId);
          break;

        case FileJobType.CLEANUP_EXPIRED:
          success = await this.storageService.cleanupExpiredFiles();
          break;

        default:
          this.logger.error(`Unknown file job type: ${type}`);
          throw new Error(`Unknown file job type: ${type}`);
      }

      if (!success) {
        throw new Error('File processing returned false');
      }

      this.logger.log(`File job ${job.id} completed successfully`);
    } catch (error) {
      this.logger.error(
        `❌ File job ${job.id} failed (Attempt ${job.attemptsMade + 1}):`,
        error.message,
      );

      // If this was the last attempt, log it as a critical failure
      if (job.opts.attempts && job.attemptsMade >= job.opts.attempts - 1) {
        this.logger.error(
          `🚨 File job ${job.id} permanently failed after ${job.opts.attempts} attempts`,
        );
        this.logger.error(`Failed file job details:`, {
          type,
          fileId,
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
  onActive(job: Job<FileJobData>) {
    this.logger.debug(
      `Processing job ${job.id} of type ${job.data.type} for file ${job.data.fileId}`,
    );
  }

  /**
   * Event handler: Called when a job completes successfully
   */
  @OnQueueCompleted()
  onCompleted(job: Job<FileJobData>) {
    this.logger.debug(`Job ${job.id} completed successfully`);
  }

  /**
   * Event handler: Called when a job fails permanently
   */
  @OnQueueFailed()
  onFailed(job: Job<FileJobData>, error: Error) {
    this.logger.error(
      `Job ${job.id} failed permanently after ${job.attemptsMade} attempts:`,
      error.message,
    );
  }
}
