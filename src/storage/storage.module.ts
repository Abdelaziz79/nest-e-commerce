// src/storage/storage.module.ts
import { BullAdapter } from '@bull-board/api/bullAdapter';
import { BullBoardModule } from '@bull-board/nestjs';
import { BullModule } from '@nestjs/bull';
import { Logger, Module, OnModuleInit } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { MulterModule } from '@nestjs/platform-express';
import * as fs from 'fs';
import { AppConfigModule } from 'src/config/app.config.module';
import { UPLOAD_DIRECTORIES } from './config/multer.config';
import { FileProcessor } from './processors/file.processor';
import { File, FileSchema } from './schemas/file.schema';
import { StorageAdminController } from './storage-admin.controller';
import { StorageQueueService } from './storage-queue.service';
import { StorageController } from './storage.controller';
import { StorageResolver } from './storage.resolver';
import { StorageService } from './storage.service';

@Module({
  imports: [
    AppConfigModule,
    MongooseModule.forFeature([{ name: File.name, schema: FileSchema }]),

    // Register the file-processing queue
    BullModule.registerQueue({
      name: 'file-processing',
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000,
        },
        removeOnComplete: {
          age: 3600, // 1 hour
          count: 100,
        },
        removeOnFail: {
          age: 86400, // 24 hours
          count: 500,
        },
      },
    }),

    // Add queue to Bull Board
    BullBoardModule.forFeature({
      name: 'file-processing',
      adapter: BullAdapter,
    }),

    // Multer configuration (for REST endpoints)
    MulterModule.register({
      dest: './uploads',
    }),
  ],
  controllers: [StorageController, StorageAdminController],
  providers: [
    StorageService,
    StorageQueueService,
    StorageResolver,
    FileProcessor,
  ],
  exports: [StorageService, StorageQueueService],
})
export class StorageModule implements OnModuleInit {
  private readonly logger = new Logger(StorageModule.name);

  onModuleInit() {
    this.ensureUploadDirectoriesExist();
  }

  private ensureUploadDirectoriesExist() {
    const directories = Object.values(UPLOAD_DIRECTORIES);
    const allDirectories = ['./uploads', ...directories];

    for (const dir of allDirectories) {
      if (!fs.existsSync(dir)) {
        try {
          fs.mkdirSync(dir, { recursive: true });
          this.logger.log(`📂 Created directory: ${dir}`);
        } catch (error) {
          this.logger.error(`❌ Failed to create directory ${dir}:`, error);
        }
      }
    }
  }
}
