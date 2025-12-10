// src/storage/schemas/file.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum FileTypeEnum {
  AVATAR = 'avatar',
  PRODUCT_IMAGE = 'product_image',
  PRODUCT_THUMBNAIL = 'product_thumbnail',
  CATEGORY_IMAGE = 'category_image',
  DOCUMENT = 'document',
  OTHER = 'other',
}

export enum FileStatus {
  PENDING = 'pending', // Uploaded but not processed
  PROCESSING = 'processing', // Being optimized/resized
  COMPLETED = 'completed', // Ready to use
  FAILED = 'failed', // Processing failed
}

@Schema({ timestamps: true })
export class File extends Document {
  @Prop({ required: true })
  originalName: string;

  @Prop({ required: true })
  filename: string; // Unique generated filename

  @Prop({ required: true })
  path: string; // Full file path on disk

  @Prop({ required: true })
  url: string; // Public URL to access the file

  @Prop({ required: true })
  mimetype: string;

  @Prop({ required: true })
  size: number; // In bytes

  @Prop({ type: String, enum: FileTypeEnum, required: true })
  type: FileTypeEnum;

  @Prop({ type: String, enum: FileStatus, default: FileStatus.PENDING })
  status: FileStatus;

  @Prop({ type: String, required: true })
  uploadedBy: string; // User ID

  @Prop()
  optimizedPath?: string; // Path to optimized version

  @Prop()
  optimizedUrl?: string; // URL to optimized version

  @Prop()
  optimizedSize?: number; // Size of optimized file

  @Prop({ type: Object })
  metadata?: {
    width?: number;
    height?: number;
    format?: string;
    aspectRatio?: string;
    [key: string]: any;
  };

  @Prop({ type: [String], default: [] })
  variants?: string[]; // URLs of different sizes (thumbnail, medium, large)

  @Prop()
  errorMessage?: string; // If processing failed

  @Prop({ default: false })
  isPublic: boolean;

  @Prop()
  expiresAt?: Date; // For temporary files

  @Prop({ type: String })
  relatedEntity?: string; // E.g., 'user', 'product'

  @Prop({ type: String })
  relatedEntityId?: string; // ID of related entity
}

export const FileSchema = SchemaFactory.createForClass(File);

// Indexes
FileSchema.index({ filename: 1 }, { unique: true });
FileSchema.index({ uploadedBy: 1 });
FileSchema.index({ type: 1 });
FileSchema.index({ status: 1 });
FileSchema.index({ relatedEntity: 1, relatedEntityId: 1 });
FileSchema.index({ expiresAt: 1 }, { sparse: true, expireAfterSeconds: 0 });
FileSchema.index({ createdAt: 1 });
