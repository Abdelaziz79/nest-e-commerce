// notifications/dto/notification.input.ts

import { Field, ID, InputType, registerEnumType } from '@nestjs/graphql';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  Max,
  Min,
  ValidateNested,
} from 'class-validator';
import { GraphQLJSONObject } from 'graphql-type-json';
import {
  NotificationChannel,
  NotificationPriority,
  NotificationType,
} from '../schemas/notification.schema';

// Register enums
registerEnumType(NotificationType, {
  name: 'NotificationType',
});

registerEnumType(NotificationPriority, {
  name: 'NotificationPriority',
});

registerEnumType(NotificationChannel, {
  name: 'NotificationChannel',
});

@InputType()
export class CreateNotificationInput {
  @Field()
  @IsString()
  @IsNotEmpty()
  title: string;

  @Field()
  @IsString()
  @IsNotEmpty()
  message: string;

  @Field(() => NotificationType)
  @IsEnum(NotificationType)
  type: NotificationType;

  @Field(() => NotificationPriority, { nullable: true })
  @IsOptional()
  @IsEnum(NotificationPriority)
  priority?: NotificationPriority;

  @Field(() => [NotificationChannel], { nullable: true })
  @IsOptional()
  @IsArray()
  @IsEnum(NotificationChannel, { each: true })
  channels?: NotificationChannel[];

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  actionUrl?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  actionText?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  imageUrl?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  icon?: string;

  // FIX: Use GraphQLJSONObject instead of Record<string, any>
  @Field(() => GraphQLJSONObject, { nullable: true })
  @IsOptional()
  @IsObject()
  data?: Record<string, any>;
}

@InputType()
export class MarkNotificationsInput {
  @Field(() => [ID])
  @IsArray()
  @IsString({ each: true })
  notificationIds: string[];

  @Field()
  @IsBoolean()
  isRead: boolean;
}

@InputType()
export class NotificationFiltersInput {
  @Field(() => NotificationType, { nullable: true })
  @IsOptional()
  @IsEnum(NotificationType)
  type?: NotificationType;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  isRead?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  archived?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  @Min(1)
  page?: number;

  @Field({ nullable: true })
  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  @Min(1)
  @Max(100)
  limit?: number;
}

@InputType()
export class QuietHoursInput {
  @Field()
  @IsBoolean()
  enabled: boolean;

  @Field()
  @IsNumber()
  @Min(0)
  @Max(23)
  startHour: number;

  @Field()
  @IsNumber()
  @Min(0)
  @Max(23)
  endHour: number;

  @Field()
  @IsString()
  timezone: string;
}

@InputType()
export class TypePreferenceInput {
  @Field(() => NotificationType)
  @IsEnum(NotificationType)
  type: NotificationType;

  @Field(() => [NotificationChannel])
  @IsArray()
  @IsEnum(NotificationChannel, { each: true })
  channels: NotificationChannel[];

  @Field()
  @IsBoolean()
  enabled: boolean;
}

@InputType()
export class UpdateNotificationPreferencesInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  emailEnabled?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  pushEnabled?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  smsEnabled?: boolean;

  @Field(() => QuietHoursInput, { nullable: true })
  @IsOptional()
  @ValidateNested()
  @Type(() => QuietHoursInput)
  quietHours?: QuietHoursInput;

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  enableDigest?: boolean;

  @Field({ nullable: true })
  @IsOptional()
  @IsEnum(['daily', 'weekly'])
  digestFrequency?: 'daily' | 'weekly';

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  digestTime?: string;

  @Field(() => [TypePreferenceInput], { nullable: true })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => TypePreferenceInput)
  typePreferences?: TypePreferenceInput[];

  @Field({ nullable: true })
  @IsOptional()
  @IsBoolean()
  doNotDisturb?: boolean;
}

@InputType()
export class BulkNotificationInput {
  @Field(() => [ID])
  @IsArray()
  @IsString({ each: true })
  userIds: string[];

  @Field()
  @IsString()
  @IsNotEmpty()
  title: string;

  @Field()
  @IsString()
  @IsNotEmpty()
  message: string;

  @Field(() => NotificationType)
  @IsEnum(NotificationType)
  type: NotificationType;

  @Field(() => NotificationPriority, { nullable: true })
  @IsOptional()
  @IsEnum(NotificationPriority)
  priority?: NotificationPriority;

  @Field(() => [NotificationChannel], { nullable: true })
  @IsOptional()
  @IsArray()
  @IsEnum(NotificationChannel, { each: true })
  channels?: NotificationChannel[];

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  actionUrl?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  actionText?: string;
}
