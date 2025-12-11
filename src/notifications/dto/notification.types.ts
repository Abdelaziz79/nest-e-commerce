// src/notifications/dto/notification.types.ts

import { Field, ID, ObjectType } from '@nestjs/graphql';
import { GraphQLJSONObject } from 'graphql-type-json';
import {
  NotificationChannel,
  NotificationPriority,
  NotificationType,
} from '../schemas/notification.schema';

@ObjectType()
export class NotificationType_GQL {
  @Field(() => ID)
  _id: string;

  @Field(() => ID)
  userId: string;

  @Field()
  title: string;

  @Field()
  message: string;

  @Field(() => NotificationType)
  type: NotificationType;

  @Field(() => NotificationPriority)
  priority: NotificationPriority;

  @Field(() => [NotificationChannel])
  channels: NotificationChannel[];

  @Field()
  isRead: boolean;

  @Field({ nullable: true })
  readAt?: Date;

  // FIX: Use GraphQLJSONObject instead of Record<string, any>
  @Field(() => GraphQLJSONObject, { nullable: true })
  data?: Record<string, any>;

  @Field({ nullable: true })
  actionUrl?: string;

  @Field({ nullable: true })
  actionText?: string;

  @Field({ nullable: true })
  imageUrl?: string;

  @Field({ nullable: true })
  icon?: string;

  @Field()
  emailSent: boolean;

  @Field({ nullable: true })
  emailSentAt?: Date;

  @Field()
  pushSent: boolean;

  @Field({ nullable: true })
  pushSentAt?: Date;

  @Field({ nullable: true })
  expiresAt?: Date;

  @Field({ nullable: true })
  relatedEntity?: string;

  @Field({ nullable: true })
  relatedEntityId?: string;

  @Field()
  archived: boolean;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

@ObjectType()
export class PaginatedNotificationsType {
  @Field(() => [NotificationType_GQL])
  notifications: NotificationType_GQL[];

  @Field()
  total: number;

  @Field()
  unreadCount: number;

  @Field()
  page: number;

  @Field()
  limit: number;

  @Field()
  totalPages: number;
}

@ObjectType()
export class NotificationStatsType {
  @Field()
  total: number;

  @Field()
  unread: number;

  @Field()
  read: number;

  @Field()
  archived: number;

  @Field(() => [NotificationTypeCount])
  byType: NotificationTypeCount[];
}

@ObjectType()
export class NotificationTypeCount {
  @Field(() => NotificationType)
  type: NotificationType;

  @Field()
  count: number;

  @Field()
  unreadCount: number;
}

@ObjectType()
export class QuietHoursType {
  @Field()
  enabled: boolean;

  @Field()
  startHour: number;

  @Field()
  endHour: number;

  @Field()
  timezone: string;
}

@ObjectType()
export class TypePreferenceType {
  @Field(() => NotificationType)
  type: NotificationType;

  @Field(() => [NotificationChannel])
  channels: NotificationChannel[];

  @Field()
  enabled: boolean;
}

@ObjectType()
export class NotificationPreferencesType {
  @Field(() => ID)
  _id: string;

  @Field(() => ID)
  userId: string;

  @Field()
  enabled: boolean;

  @Field()
  emailEnabled: boolean;

  @Field()
  pushEnabled: boolean;

  @Field()
  smsEnabled: boolean;

  @Field(() => QuietHoursType, { nullable: true })
  quietHours?: QuietHoursType;

  @Field()
  enableDigest: boolean;

  @Field({ nullable: true })
  digestFrequency?: string;

  @Field({ nullable: true })
  digestTime?: string;

  @Field(() => [TypePreferenceType])
  typePreferences: TypePreferenceType[];

  @Field()
  doNotDisturb: boolean;

  @Field({ nullable: true })
  doNotDisturbUntil?: Date;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}

@ObjectType()
export class BulkNotificationResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;

  @Field()
  successCount: number;

  @Field()
  failureCount: number;

  @Field(() => [String])
  errors: string[];
}
