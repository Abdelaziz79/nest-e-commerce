// src/notifications/schemas/notification.schema.ts

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export enum NotificationType {
  ORDER_PLACED = 'order_placed',
  ORDER_CONFIRMED = 'order_confirmed',
  ORDER_SHIPPED = 'order_shipped',
  ORDER_DELIVERED = 'order_delivered',
  ORDER_CANCELLED = 'order_cancelled',
  PAYMENT_SUCCESS = 'payment_success',
  PAYMENT_FAILED = 'payment_failed',
  PRODUCT_BACK_IN_STOCK = 'product_back_in_stock',
  PRICE_DROP = 'price_drop',
  WISHLIST_ITEM_SALE = 'wishlist_item_sale',
  REVIEW_REPLY = 'review_reply',
  ACCOUNT_SECURITY = 'account_security',
  PROMOTIONAL = 'promotional',
  SYSTEM = 'system',
  ADMIN_MESSAGE = 'admin_message',
  TWO_FACTOR_ENABLED = 'two_factor_enabled',
  PASSWORD_CHANGED = 'password_changed',
  EMAIL_VERIFIED = 'email_verified',
  WELCOME = 'welcome',
}

export enum NotificationPriority {
  LOW = 'low',
  NORMAL = 'normal',
  HIGH = 'high',
  URGENT = 'urgent',
}

export enum NotificationChannel {
  IN_APP = 'in_app',
  EMAIL = 'email',
  PUSH = 'push',
  SMS = 'sms',
}

@Schema({ timestamps: true })
export class Notification extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId: Types.ObjectId;

  @Prop({ required: true, trim: true })
  title: string;

  @Prop({ required: true })
  message: string;

  @Prop({ type: String, enum: NotificationType, required: true, index: true })
  type: NotificationType;

  @Prop({
    type: String,
    enum: NotificationPriority,
    default: NotificationPriority.NORMAL,
  })
  priority: NotificationPriority;

  @Prop({
    type: [String],
    enum: NotificationChannel,
    default: [NotificationChannel.IN_APP],
  })
  channels: NotificationChannel[];

  @Prop({ default: false, index: true })
  isRead: boolean;

  @Prop()
  readAt?: Date;

  @Prop({ type: Object })
  data?: Record<string, any>;

  @Prop()
  actionUrl?: string;

  @Prop()
  actionText?: string;

  @Prop()
  imageUrl?: string;

  @Prop()
  icon?: string;

  @Prop({ default: false })
  emailSent: boolean;

  @Prop()
  emailSentAt?: Date;

  @Prop({ default: false })
  pushSent: boolean;

  @Prop()
  pushSentAt?: Date;

  @Prop()
  expiresAt?: Date;

  @Prop({ type: String })
  relatedEntity?: string;

  @Prop({ type: Types.ObjectId })
  relatedEntityId?: Types.ObjectId;

  @Prop({ default: false })
  archived: boolean;

  @Prop()
  createdAt: Date;
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);

// Indexes
NotificationSchema.index({ userId: 1, isRead: 1 });
NotificationSchema.index({ userId: 1, type: 1 });
NotificationSchema.index({ userId: 1, createdAt: -1 });
NotificationSchema.index({ userId: 1, priority: 1 });
NotificationSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0, sparse: true },
);

// Compound index for efficient queries
NotificationSchema.index({ userId: 1, isRead: 1, archived: 1, createdAt: -1 });
