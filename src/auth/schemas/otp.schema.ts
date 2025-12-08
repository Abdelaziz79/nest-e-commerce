// src/auth/schemas/otp.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum OtpType {
  EMAIL_VERIFICATION = 'email_verification',
  PASSWORD_RESET = 'password_reset',
  TWO_FACTOR = 'two_factor',
  ACCOUNT_DELETION = 'account_deletion',
}

@Schema({ timestamps: true })
export class Otp extends Document {
  @Prop({ required: true, lowercase: true, trim: true })
  email: string;

  @Prop({ required: true })
  code: string;

  @Prop({ required: true, enum: OtpType })
  type: OtpType;

  @Prop({ required: true })
  expiresAt: Date;

  @Prop({ default: false })
  isUsed: boolean;

  @Prop({ default: 0 })
  attempts: number;

  @Prop({ type: String })
  userId?: string;

  @Prop()
  ipAddress?: string;

  @Prop()
  userAgent?: string;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);

OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
OtpSchema.index({ email: 1, type: 1, isUsed: 1 });
