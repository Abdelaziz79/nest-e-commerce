// src/notifications/notifications.module.ts

import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { AppConfigModule } from 'src/config/app.config.module';
import { AppConfigService } from 'src/config/app.config.service';
import { MailModule } from 'src/mail/mail.module';
import { NotificationHelperService } from './notification-helper.service';
import { NotificationTemplatesService } from './notification-templates.service';
import { NotificationsGateway } from './notifications.gateway';
import { NotificationsResolver } from './notifications.resolver';
import { NotificationsService } from './notifications.service';
import {
  NotificationPreferences,
  NotificationPreferencesSchema,
} from './schemas/notification-preferences.schema';
import {
  Notification,
  NotificationSchema,
} from './schemas/notification.schema';

@Module({
  imports: [
    AppConfigModule,
    MailModule,
    MongooseModule.forFeature([
      { name: Notification.name, schema: NotificationSchema },
      {
        name: NotificationPreferences.name,
        schema: NotificationPreferencesSchema,
      },
    ]),
    JwtModule.registerAsync({
      imports: [AppConfigModule],
      inject: [AppConfigService],
      useFactory: async (configService: AppConfigService) => ({
        secret: configService.jwtSecret,
        signOptions: { expiresIn: configService.jwtExpiration },
      }),
    }),
  ],
  providers: [
    NotificationsService,
    NotificationsResolver,
    NotificationsGateway,
    NotificationTemplatesService,
    NotificationHelperService,
  ],
  exports: [
    NotificationsService,
    NotificationHelperService,
    NotificationsGateway,
  ],
})
export class NotificationsModule {}
