// src/users/schemas/user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum UserRole {
  CUSTOMER = 'customer',
  ADMIN = 'admin',
  SUPER_ADMIN = 'super_admin',
  VENDOR = 'vendor',
  MODERATOR = 'moderator',
  SUPPORT = 'support',
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  BANNED = 'banned',
  PENDING = 'pending',
  SUSPENDED = 'suspended',
}

@Schema()
export class Address {
  _id: string; // MongoDB will auto-generate this

  @Prop({ required: true })
  address: string;

  @Prop({ required: true })
  city: string;

  @Prop({ required: true })
  country: string;

  @Prop({ required: true })
  postalCode: string;

  @Prop({ required: true })
  phoneNumber: string;

  @Prop({ default: false })
  isDefault: boolean;

  @Prop()
  label: string; // "Home", "Work", etc.

  @Prop()
  recipientName: string;

  @Prop()
  recipientPhone: string;

  @Prop()
  instructions: string; // Delivery instructions

  @Prop({ type: { lat: Number, lng: Number } })
  coordinates: {
    lat: number;
    lng: number;
  };

  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export const AddressSchema = SchemaFactory.createForClass(Address);

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true, trim: true })
  firstName: string;

  @Prop({ required: true, trim: true })
  lastName: string;

  @Prop({ unique: true, sparse: true, trim: true, lowercase: true })
  username: string;

  @Prop()
  displayName: string;

  @Prop({ required: true, unique: true, lowercase: true, trim: true })
  email: string;

  @Prop({ required: true, select: false })
  password: string;

  @Prop({ type: String, enum: UserRole, default: UserRole.CUSTOMER })
  role: UserRole;

  @Prop({ type: String, enum: UserStatus, default: UserStatus.PENDING })
  status: UserStatus;

  @Prop()
  banReason: string;

  @Prop()
  bannedAt: Date;

  @Prop({ type: String })
  bannedBy: string; // User ID of admin who banned

  @Prop()
  avatar: string;

  @Prop({ type: [AddressSchema], default: [] })
  addresses: Address[];

  @Prop({ default: false })
  isEmailVerified: boolean;

  @Prop({ select: false })
  emailVerificationToken: string;

  @Prop({ select: false })
  emailVerificationExpires: Date;

  @Prop({ select: false })
  passwordResetToken: string;

  @Prop({ select: false })
  passwordResetExpires: Date;

  @Prop({ trim: true })
  phone: string;

  @Prop({ default: false })
  phoneVerified: boolean;

  @Prop({ select: false })
  phoneVerificationToken: string;

  @Prop({ select: false })
  phoneVerificationExpires: Date;

  @Prop()
  lastLogin: Date;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: 'en' })
  preferredLanguage: string;

  @Prop({ default: 'USD' })
  preferredCurrency: string;

  @Prop()
  dateOfBirth: Date;

  @Prop()
  gender: string;

  @Prop({ default: false })
  twoFactorEnabled: boolean;

  @Prop({ select: false })
  twoFactorSecret: string;

  @Prop({ type: [String], select: false })
  refreshTokens: string[];

  @Prop({ default: 0 })
  loginAttempts: number;

  @Prop()
  lockUntil: Date;

  @Prop({ default: false })
  newsletter: boolean;

  @Prop()
  termsAcceptedAt: Date;

  @Prop()
  privacyPolicyAcceptedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Virtual for full name
UserSchema.virtual('fullName').get(function (this: User) {
  return `${this.firstName} ${this.lastName}`;
});

// Ensure virtuals are included in JSON
UserSchema.set('toJSON', { virtuals: true });
UserSchema.set('toObject', { virtuals: true });

// Indexes for better query performance
UserSchema.index({ email: 1 });
UserSchema.index({ username: 1 });
UserSchema.index({ phone: 1 });
UserSchema.index({ role: 1 });
UserSchema.index({ status: 1 });
