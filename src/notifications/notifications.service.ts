// src/notifications/notifications.service.ts

import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import type { Cache } from 'cache-manager';
import { Model, Types } from 'mongoose';
import { MailQueueService } from 'src/mail/mail-queue.service';
import {
  BulkNotificationInput,
  CreateNotificationInput,
  NotificationFiltersInput,
  UpdateNotificationPreferencesInput,
} from './dto/notification.input';
import { NotificationsGateway } from './notifications.gateway';
import {
  NotificationPreferences,
  TypePreference,
} from './schemas/notification-preferences.schema';
import {
  Notification,
  NotificationChannel,
  NotificationType,
} from './schemas/notification.schema';

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);

  constructor(
    @InjectModel(Notification.name)
    private readonly notificationModel: Model<Notification>,
    @InjectModel(NotificationPreferences.name)
    private readonly preferencesModel: Model<NotificationPreferences>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly mailQueueService: MailQueueService,
    private readonly notificationsGateway: NotificationsGateway,
  ) {}

  // ==========================================
  // CREATE NOTIFICATIONS
  // ==========================================

  async createNotification(
    userId: string,
    input: CreateNotificationInput,
  ): Promise<Notification | null> {
    try {
      // Get user preferences
      const preferences = await this.getUserPreferences(userId);

      // Check if notifications are enabled
      if (!preferences.enabled) {
        this.logger.debug(
          `Notifications disabled for user ${userId}, skipping`,
        );
        return null;
      }

      // Check Do Not Disturb
      if (preferences.doNotDisturb) {
        if (
          !preferences.doNotDisturbUntil ||
          preferences.doNotDisturbUntil > new Date()
        ) {
          this.logger.debug(`User ${userId} is in DND mode, skipping`);
          return null;
        }
      }

      // Check quiet hours
      if (this.isInQuietHours(preferences)) {
        this.logger.debug(`User ${userId} is in quiet hours, skipping`);
        return null;
      }

      // Filter channels based on preferences
      const allowedChannels = this.filterChannelsByPreferences(
        input.channels || [NotificationChannel.IN_APP],
        input.type,
        preferences,
      );

      if (allowedChannels.length === 0) {
        this.logger.debug(
          `No allowed channels for user ${userId}, skipping notification`,
        );
        return null;
      }

      // Create notification
      const notification = await this.notificationModel.create({
        userId: new Types.ObjectId(userId),
        title: input.title,
        message: input.message,
        type: input.type,
        priority: input.priority,
        channels: allowedChannels,
        actionUrl: input.actionUrl,
        actionText: input.actionText,
        imageUrl: input.imageUrl,
        icon: input.icon,
        data: input.data,
      });

      // Send through different channels
      await this.sendThroughChannels(notification, preferences);

      // Invalidate cache
      await this.invalidateUserCache(userId);

      this.logger.log(
        `Notification created for user ${userId}: ${notification._id}`,
      );

      return notification;
    } catch (error) {
      this.logger.error(`Failed to create notification: ${error.message}`);
      throw error;
    }
  }

  async createBulkNotifications(input: BulkNotificationInput): Promise<{
    success: boolean;
    successCount: number;
    failureCount: number;
    errors: string[];
  }> {
    const results: {
      success: boolean;
      successCount: number;
      failureCount: number;
      errors: string[];
    } = {
      success: true,
      successCount: 0,
      failureCount: 0,
      errors: [],
    };

    for (const userId of input.userIds) {
      try {
        await this.createNotification(userId, {
          title: input.title,
          message: input.message,
          type: input.type,
          priority: input.priority,
          channels: input.channels,
          actionUrl: input.actionUrl,
          actionText: input.actionText,
        });
        results.successCount++;
      } catch (error) {
        results.failureCount++;
        results.errors.push(`User ${userId}: ${error.message}`);
      }
    }

    if (results.failureCount > 0) {
      results.success = false;
    }

    this.logger.log(
      `Bulk notification sent: ${results.successCount} success, ${results.failureCount} failed`,
    );

    return results;
  }

  // ==========================================
  // SEND THROUGH CHANNELS
  // ==========================================

  private async sendThroughChannels(
    notification: Notification,
    preferences: NotificationPreferences,
  ): Promise<void> {
    const promises: Promise<void>[] = [];

    // Send in-app notification (WebSocket)
    if (notification.channels.includes(NotificationChannel.IN_APP)) {
      promises.push(this.sendInAppNotification(notification));
    }

    // Send email
    if (
      notification.channels.includes(NotificationChannel.EMAIL) &&
      preferences.emailEnabled
    ) {
      promises.push(this.sendEmailNotification(notification));
    }

    // Send push notification
    if (
      notification.channels.includes(NotificationChannel.PUSH) &&
      preferences.pushEnabled
    ) {
      promises.push(this.sendPushNotification(notification));
    }

    await Promise.allSettled(promises);
  }

  private async sendInAppNotification(
    notification: Notification,
  ): Promise<void> {
    try {
      this.notificationsGateway.sendToUser(
        notification.userId.toString(),
        'notification',
        {
          _id: notification._id.toString(),
          title: notification.title,
          message: notification.message,
          type: notification.type,
          priority: notification.priority,
          actionUrl: notification.actionUrl,
          actionText: notification.actionText,
          imageUrl: notification.imageUrl,
          icon: notification.icon,
          createdAt: notification.createdAt,
        },
      );
      this.logger.debug(
        `In-app notification sent to user ${notification.userId}`,
      );
    } catch (error) {
      this.logger.error(`Failed to send in-app notification: ${error.message}`);
    }
  }

  private async sendEmailNotification(
    notification: Notification,
  ): Promise<void> {
    try {
      await this.notificationModel.findByIdAndUpdate(notification._id, {
        emailSent: true,
        emailSentAt: new Date(),
      });

      this.logger.debug(
        `Email notification queued for user ${notification.userId}`,
      );
    } catch (error) {
      this.logger.error(`Failed to send email notification: ${error.message}`);
    }
  }

  private async sendPushNotification(
    notification: Notification,
  ): Promise<void> {
    try {
      await this.notificationModel.findByIdAndUpdate(notification._id, {
        pushSent: true,
        pushSentAt: new Date(),
      });

      this.logger.debug(
        `Push notification sent to user ${notification.userId}`,
      );
    } catch (error) {
      this.logger.error(`Failed to send push notification: ${error.message}`);
    }
  }

  // ==========================================
  // READ NOTIFICATIONS
  // ==========================================

  async getUserNotifications(
    userId: string,
    filters?: NotificationFiltersInput,
  ) {
    const {
      type,
      isRead,
      archived = false,
      page = 1,
      limit = 20,
    } = filters || {};

    const query: any = {
      userId: new Types.ObjectId(userId),
      archived,
    };

    if (type) query.type = type;
    if (isRead !== undefined) query.isRead = isRead;

    const skip = (page - 1) * limit;

    const [notifications, total, unreadCount] = await Promise.all([
      this.notificationModel
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      this.notificationModel.countDocuments(query),
      this.notificationModel.countDocuments({
        userId: new Types.ObjectId(userId),
        isRead: false,
        archived: false,
      }),
    ]);

    return {
      notifications,
      total,
      unreadCount,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async getNotificationById(
    notificationId: string,
    userId: string,
  ): Promise<Notification> {
    const notification = await this.notificationModel.findOne({
      _id: notificationId,
      userId: new Types.ObjectId(userId),
    });

    if (!notification) {
      throw new NotFoundException('Notification not found');
    }

    return notification;
  }

  async getNotificationStats(userId: string) {
    const userObjectId = new Types.ObjectId(userId);

    const [total, unread, read, archived, byType] = await Promise.all([
      this.notificationModel.countDocuments({ userId: userObjectId }),
      this.notificationModel.countDocuments({
        userId: userObjectId,
        isRead: false,
        archived: false,
      }),
      this.notificationModel.countDocuments({
        userId: userObjectId,
        isRead: true,
      }),
      this.notificationModel.countDocuments({
        userId: userObjectId,
        archived: true,
      }),
      this.notificationModel.aggregate([
        { $match: { userId: userObjectId } },
        {
          $group: {
            _id: '$type',
            count: { $sum: 1 },
            unreadCount: {
              $sum: { $cond: [{ $eq: ['$isRead', false] }, 1, 0] },
            },
          },
        },
      ]),
    ]);

    return {
      total,
      unread,
      read,
      archived,
      byType: byType.map((item) => ({
        type: item._id,
        count: item.count,
        unreadCount: item.unreadCount,
      })),
    };
  }

  // ==========================================
  // UPDATE NOTIFICATIONS
  // ==========================================

  async markAsRead(notificationIds: string[], userId: string): Promise<number> {
    const result = await this.notificationModel.updateMany(
      {
        _id: { $in: notificationIds.map((id) => new Types.ObjectId(id)) },
        userId: new Types.ObjectId(userId),
      },
      {
        $set: {
          isRead: true,
          readAt: new Date(),
        },
      },
    );

    await this.invalidateUserCache(userId);

    this.notificationsGateway.sendToUser(userId, 'notifications_updated', {
      action: 'marked_read',
      count: result.modifiedCount,
    });

    return result.modifiedCount;
  }

  async markAsUnread(
    notificationIds: string[],
    userId: string,
  ): Promise<number> {
    const result = await this.notificationModel.updateMany(
      {
        _id: { $in: notificationIds.map((id) => new Types.ObjectId(id)) },
        userId: new Types.ObjectId(userId),
      },
      {
        $set: {
          isRead: false,
          readAt: null,
        },
      },
    );

    await this.invalidateUserCache(userId);

    this.notificationsGateway.sendToUser(userId, 'notifications_updated', {
      action: 'marked_unread',
      count: result.modifiedCount,
    });

    return result.modifiedCount;
  }

  async markAllAsRead(userId: string): Promise<number> {
    const result = await this.notificationModel.updateMany(
      {
        userId: new Types.ObjectId(userId),
        isRead: false,
      },
      {
        $set: {
          isRead: true,
          readAt: new Date(),
        },
      },
    );

    await this.invalidateUserCache(userId);

    this.notificationsGateway.sendToUser(userId, 'notifications_updated', {
      action: 'marked_all_read',
      count: result.modifiedCount,
    });

    return result.modifiedCount;
  }

  async archiveNotifications(
    notificationIds: string[],
    userId: string,
  ): Promise<number> {
    const result = await this.notificationModel.updateMany(
      {
        _id: { $in: notificationIds.map((id) => new Types.ObjectId(id)) },
        userId: new Types.ObjectId(userId),
      },
      {
        $set: { archived: true },
      },
    );

    await this.invalidateUserCache(userId);

    return result.modifiedCount;
  }

  async deleteNotifications(
    notificationIds: string[],
    userId: string,
  ): Promise<number> {
    const result = await this.notificationModel.deleteMany({
      _id: { $in: notificationIds.map((id) => new Types.ObjectId(id)) },
      userId: new Types.ObjectId(userId),
    });

    await this.invalidateUserCache(userId);

    return result.deletedCount;
  }

  async deleteAllRead(userId: string): Promise<number> {
    const result = await this.notificationModel.deleteMany({
      userId: new Types.ObjectId(userId),
      isRead: true,
    });

    await this.invalidateUserCache(userId);

    return result.deletedCount;
  }

  // ==========================================
  // PREFERENCES
  // ==========================================

  async getUserPreferences(userId: string): Promise<NotificationPreferences> {
    const cacheKey = `notification_prefs:${userId}`;
    const cached =
      await this.cacheManager.get<NotificationPreferences>(cacheKey);

    if (cached) return cached;

    let preferences = await this.preferencesModel
      .findOne({
        userId: new Types.ObjectId(userId),
      })
      .exec();

    if (!preferences) {
      preferences = (await this.createDefaultPreferences(userId)) as any;
    }

    // Convert to plain object for caching
    const preferencesObj = preferences?.toObject();
    await this.cacheManager.set(cacheKey, preferencesObj, 300000);

    return preferences as NotificationPreferences;
  }

  async updateUserPreferences(
    userId: string,
    input: UpdateNotificationPreferencesInput,
  ): Promise<NotificationPreferences> {
    let preferences = await this.preferencesModel
      .findOne({
        userId: new Types.ObjectId(userId),
      })
      .exec();

    if (!preferences) {
      preferences = (await this.createDefaultPreferences(userId)) as any;
    }

    // FIX: Use $set operator to update only provided fields
    const updateFields: any = {};

    // Only include fields that are actually provided
    if (input.enabled !== undefined) updateFields.enabled = input.enabled;
    if (input.emailEnabled !== undefined)
      updateFields.emailEnabled = input.emailEnabled;
    if (input.pushEnabled !== undefined)
      updateFields.pushEnabled = input.pushEnabled;
    if (input.smsEnabled !== undefined)
      updateFields.smsEnabled = input.smsEnabled;
    if (input.quietHours !== undefined)
      updateFields.quietHours = input.quietHours;
    if (input.enableDigest !== undefined)
      updateFields.enableDigest = input.enableDigest;
    if (input.digestFrequency !== undefined)
      updateFields.digestFrequency = input.digestFrequency;
    if (input.digestTime !== undefined)
      updateFields.digestTime = input.digestTime;
    if (input.typePreferences !== undefined)
      updateFields.typePreferences = input.typePreferences;
    if (input.doNotDisturb !== undefined)
      updateFields.doNotDisturb = input.doNotDisturb;

    // Update the document using findByIdAndUpdate with $set
    const updatedPreferences = await this.preferencesModel.findOneAndUpdate(
      { userId: new Types.ObjectId(userId) },
      { $set: updateFields },
      { new: true, runValidators: false }, // Don't run validators on partial update
    );

    if (!updatedPreferences) {
      throw new NotFoundException('Preferences not found');
    }

    await this.cacheManager.del(`notification_prefs:${userId}`);

    return updatedPreferences;
  }

  private async createDefaultPreferences(
    userId: string,
  ): Promise<NotificationPreferences> {
    const defaultPreferences: Partial<TypePreference>[] = Object.values(
      NotificationType,
    ).map((type) => ({
      type,
      channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL],
      enabled: true,
    }));

    const prefs = await this.preferencesModel.create({
      userId: new Types.ObjectId(userId),
      enabled: true,
      emailEnabled: true,
      pushEnabled: true,
      smsEnabled: false,
      enableDigest: false,
      doNotDisturb: false,
      typePreferences: defaultPreferences,
    });

    return prefs;
  }

  // ==========================================
  // HELPER METHODS
  // ==========================================

  private filterChannelsByPreferences(
    requestedChannels: NotificationChannel[],
    type: NotificationType,
    preferences: NotificationPreferences,
  ): NotificationChannel[] {
    const typePreference = preferences.typePreferences?.find(
      (pref) => pref.type === type,
    );

    if (typePreference && !typePreference.enabled) {
      return [];
    }

    const allowedChannels = requestedChannels.filter((channel) => {
      if (typePreference && !typePreference.channels.includes(channel)) {
        return false;
      }

      switch (channel) {
        case NotificationChannel.EMAIL:
          return preferences.emailEnabled;
        case NotificationChannel.PUSH:
          return preferences.pushEnabled;
        case NotificationChannel.SMS:
          return preferences.smsEnabled;
        case NotificationChannel.IN_APP:
          return true;
        default:
          return false;
      }
    });

    return allowedChannels;
  }

  private isInQuietHours(preferences: NotificationPreferences): boolean {
    if (!preferences.quietHours?.enabled) return false;

    const now = new Date();
    const currentHour = now.getHours();
    const { startHour, endHour } = preferences.quietHours;

    if (startHour <= endHour) {
      return currentHour >= startHour && currentHour < endHour;
    } else {
      return currentHour >= startHour || currentHour < endHour;
    }
  }

  private async invalidateUserCache(userId: string): Promise<void> {
    await this.cacheManager.del(`notifications:${userId}`);
    await this.cacheManager.del(`notification_prefs:${userId}`);
  }
}
