// src/mail/mail.module.ts

import { BullAdapter } from '@bull-board/api/bullAdapter';
import { ExpressAdapter } from '@bull-board/express';
import { BullBoardModule } from '@bull-board/nestjs';
import { BullModule } from '@nestjs/bull';
import { Module } from '@nestjs/common';
import { AppConfigModule } from 'src/config/app.config.module';
import { AppConfigService } from 'src/config/app.config.service';
import { MailQueueController } from './mail-queue.controller';
import { MailQueueService } from './mail-queue.service';
import { MailService } from './mail.service';
import { EmailProcessor } from './processors/email.processor';

@Module({
  imports: [
    AppConfigModule,

    BullModule.forRootAsync({
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: (configService: AppConfigService) => ({
        redis: {
          host: configService.redisHost,
          port: configService.redisPort,
          password: configService.redisPassword,
        },
        defaultJobOptions: {
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 2000,
          },
          // FIX: Keep completed jobs for 1 hour
          removeOnComplete: {
            age: 3600, // 1 hour in seconds
            count: 100, // Keep last 100
          },
          // Keep failed jobs for debugging
          removeOnFail: {
            age: 86400, // 24 hours in seconds
            count: 500, // Keep last 500
          },
        },
      }),
    }),

    // Register the email queue
    BullModule.registerQueue({
      name: 'email',
      defaultJobOptions: {
        priority: 1,
      },
    }),

    // Setup Bull Board for monitoring
    BullBoardModule.forRoot({
      route: '/admin/queues',
      adapter: ExpressAdapter,
    }),

    // Register queues to Bull Board
    BullBoardModule.forFeature({
      name: 'email',
      adapter: BullAdapter,
    }),
  ],
  controllers: [MailQueueController],
  providers: [MailService, MailQueueService, EmailProcessor],
  exports: [MailQueueService],
})
export class MailModule {}
