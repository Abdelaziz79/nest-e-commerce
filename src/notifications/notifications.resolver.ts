// src/notifications/notifications.resolver.ts

import { UseGuards } from '@nestjs/common';
import {
  Args,
  ID,
  Mutation,
  Query,
  Resolver,
  Subscription,
} from '@nestjs/graphql';
import { PubSub } from 'graphql-subscriptions';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { GqlAuthGuard } from '../auth/guards/gql-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { User } from '../users/schemas/user.schema';
import {
  BulkNotificationInput,
  CreateNotificationInput,
  MarkNotificationsInput,
  NotificationFiltersInput,
  UpdateNotificationPreferencesInput,
} from './dto/notification.input';
import {
  BulkNotificationResponse,
  NotificationPreferencesType,
  NotificationStatsType,
  NotificationType_GQL,
  PaginatedNotificationsType,
} from './dto/notification.types';
import { NotificationsService } from './notifications.service';

const pubSub = new PubSub();

@Resolver(() => NotificationType_GQL)
export class NotificationsResolver {
  constructor(private readonly notificationsService: NotificationsService) {}

  // ==========================================
  // QUERIES
  // ==========================================

  @Query(() => PaginatedNotificationsType)
  @UseGuards(GqlAuthGuard)
  async myNotifications(
    @CurrentUser() user: User,
    @Args('filters', { nullable: true }) filters?: NotificationFiltersInput,
  ) {
    return this.notificationsService.getUserNotifications(
      user._id.toString(),
      filters,
    );
  }

  @Query(() => NotificationType_GQL)
  @UseGuards(GqlAuthGuard)
  async notification(
    @CurrentUser() user: User,
    @Args('id', { type: () => ID }) id: string,
  ) {
    return this.notificationsService.getNotificationById(
      id,
      user._id.toString(),
    );
  }

  @Query(() => NotificationStatsType)
  @UseGuards(GqlAuthGuard)
  async notificationStats(@CurrentUser() user: User) {
    return this.notificationsService.getNotificationStats(user._id.toString());
  }

  @Query(() => NotificationPreferencesType)
  @UseGuards(GqlAuthGuard)
  async notificationPreferences(@CurrentUser() user: User) {
    return this.notificationsService.getUserPreferences(user._id.toString());
  }

  // ==========================================
  // MUTATIONS - USER
  // ==========================================

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async markNotificationsAsRead(
    @CurrentUser() user: User,
    @Args('input') input: MarkNotificationsInput,
  ) {
    const count = await this.notificationsService.markAsRead(
      input.notificationIds,
      user._id.toString(),
    );
    return count > 0;
  }

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async markNotificationsAsUnread(
    @CurrentUser() user: User,
    @Args('input') input: MarkNotificationsInput,
  ) {
    const count = await this.notificationsService.markAsUnread(
      input.notificationIds,
      user._id.toString(),
    );
    return count > 0;
  }

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async markAllNotificationsAsRead(@CurrentUser() user: User) {
    const count = await this.notificationsService.markAllAsRead(
      user._id.toString(),
    );
    return count > 0;
  }

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async archiveNotifications(
    @CurrentUser() user: User,
    @Args('notificationIds', { type: () => [ID] }) notificationIds: string[],
  ) {
    const count = await this.notificationsService.archiveNotifications(
      notificationIds,
      user._id.toString(),
    );
    return count > 0;
  }

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async deleteNotifications(
    @CurrentUser() user: User,
    @Args('notificationIds', { type: () => [ID] }) notificationIds: string[],
  ) {
    const count = await this.notificationsService.deleteNotifications(
      notificationIds,
      user._id.toString(),
    );
    return count > 0;
  }

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async deleteAllReadNotifications(@CurrentUser() user: User) {
    const count = await this.notificationsService.deleteAllRead(
      user._id.toString(),
    );
    return count > 0;
  }

  @Mutation(() => NotificationPreferencesType)
  @UseGuards(GqlAuthGuard)
  async updateNotificationPreferences(
    @CurrentUser() user: User,
    @Args('input') input: UpdateNotificationPreferencesInput,
  ) {
    return this.notificationsService.updateUserPreferences(
      user._id.toString(),
      input,
    );
  }

  // ==========================================
  // MUTATIONS - ADMIN
  // ==========================================

  @Mutation(() => NotificationType_GQL)
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  async createNotificationForUser(
    @Args('userId', { type: () => ID }) userId: string,
    @Args('input') input: CreateNotificationInput,
  ) {
    return this.notificationsService.createNotification(userId, input);
  }

  @Mutation(() => BulkNotificationResponse)
  @UseGuards(GqlAuthGuard, RolesGuard)
  @Roles('admin', 'super_admin')
  async sendBulkNotification(@Args('input') input: BulkNotificationInput) {
    const result =
      await this.notificationsService.createBulkNotifications(input);
    return {
      success: result.success,
      message: result.success
        ? 'Notifications sent successfully'
        : 'Some notifications failed to send',
      successCount: result.successCount,
      failureCount: result.failureCount,
      errors: result.errors,
    };
  }

  // ==========================================
  // SUBSCRIPTIONS
  // ==========================================

  @Subscription(() => NotificationType_GQL, {
    filter: (payload, variables, context) => {
      // Only send to the user who owns the notification
      return payload.newNotification.userId === context.req.user._id.toString();
    },
    resolve: (payload) => payload.newNotification,
  })
  @UseGuards(GqlAuthGuard)
  newNotification(@CurrentUser() user: User) {
    // Use proper asyncIterableIterator
    return pubSub.asyncIterableIterator('newNotification');
  }

  @Subscription(() => String, {
    filter: (payload, variables, context) => {
      return payload.userId === context.req.user._id.toString();
    },
    resolve: (payload) => payload.message,
  })
  @UseGuards(GqlAuthGuard)
  notificationUpdated(@CurrentUser() user: User) {
    // Use proper asyncIterableIterator
    return pubSub.asyncIterableIterator('notificationUpdated');
  }
}
