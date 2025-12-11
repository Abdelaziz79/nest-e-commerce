// notifications/schemas/notification-preferences.schema.ts

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { NotificationChannel, NotificationType } from './notification.schema';

@Schema()
export class TypePreference {
  @Prop({ type: String, enum: NotificationType, required: true })
  type: NotificationType;

  @Prop({ type: [String], enum: NotificationChannel, required: true })
  channels: NotificationChannel[];

  @Prop({ default: true })
  enabled: boolean;
}

export const TypePreferenceSchema =
  SchemaFactory.createForClass(TypePreference);

@Schema({ timestamps: true })
export class NotificationPreferences {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  userId: Types.ObjectId;

  // Global settings - ALL WITH DEFAULTS
  @Prop({ default: true, required: true })
  enabled: boolean;

  @Prop({ default: true, required: true })
  emailEnabled: boolean;

  @Prop({ default: true, required: true })
  pushEnabled: boolean;

  @Prop({ default: false, required: true })
  smsEnabled: boolean;

  // Quiet hours (user won't receive notifications during this time)
  @Prop({ type: Object, default: null })
  quietHours?: {
    enabled: boolean;
    startHour: number; // 0-23
    endHour: number; // 0-23
    timezone: string;
  };

  // Digest settings
  @Prop({ default: false, required: true })
  enableDigest: boolean;

  @Prop({ type: String, enum: ['daily', 'weekly'], default: null })
  digestFrequency?: 'daily' | 'weekly';

  @Prop({ default: null })
  digestTime?: string; // HH:MM format

  // Type-specific preferences
  @Prop({ type: [TypePreferenceSchema], default: [] })
  typePreferences: TypePreference[];

  // Do Not Disturb
  @Prop({ default: false, required: true })
  doNotDisturb: boolean;

  @Prop({ default: null })
  doNotDisturbUntil?: Date;
}

export type NotificationPreferencesDocument = NotificationPreferences &
  Document;

export const NotificationPreferencesSchema = SchemaFactory.createForClass(
  NotificationPreferences,
);

// Index
NotificationPreferencesSchema.index({ userId: 1 }, { unique: true });
