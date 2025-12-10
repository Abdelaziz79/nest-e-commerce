// src/storage/storage.service.ts
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { promises as fs } from 'fs';
import { Model } from 'mongoose';
import { join } from 'path';
import sharp from 'sharp';
import { AppConfigService } from 'src/config/app.config.service';
import {
  IMAGE_OPTIMIZATION,
  IMAGE_VARIANTS,
  UPLOAD_DIRECTORIES,
} from './config/multer.config';
import { File, FileStatus, FileTypeEnum } from './schemas/file.schema';
import { StorageQueueService } from './storage-queue.service';

@Injectable()
export class StorageService {
  private readonly logger = new Logger(StorageService.name);

  constructor(
    @InjectModel(File.name) private readonly fileModel: Model<File>,
    private readonly storageQueueService: StorageQueueService,
    private readonly configService: AppConfigService,
  ) {}

  // ==========================================
  // FILE UPLOAD & CREATION
  // ==========================================

  async createFileRecord(
    file: Express.Multer.File,
    fileType: FileTypeEnum,
    uploadedBy: string,
    options?: {
      relatedEntity?: string;
      relatedEntityId?: string;
      isPublic?: boolean;
    },
  ): Promise<File> {
    try {
      const baseUrl = this.configService.storageBaseUrl;
      const relativePath = file.path.replace(/\\/g, '/');
      const url = `${baseUrl}/${relativePath}`;

      const fileRecord = await this.fileModel.create({
        originalName: file.originalname,
        filename: file.filename,
        path: file.path,
        url,
        mimetype: file.mimetype,
        size: file.size,
        type: fileType,
        status: FileStatus.PENDING,
        uploadedBy,
        isPublic: options?.isPublic ?? true,
        relatedEntity: options?.relatedEntity,
        relatedEntityId: options?.relatedEntityId,
      });

      // Queue for processing
      await this.storageQueueService.processUpload(
        fileRecord._id.toString(),
        fileType,
      );

      this.logger.log(`File record created: ${fileRecord._id}`);
      return fileRecord;
    } catch (error) {
      this.logger.error('Failed to create file record:', error);
      // Clean up uploaded file
      await this.deletePhysicalFile(file.path);
      throw error;
    }
  }

  // ==========================================
  // FILE PROCESSING (Called by Queue Processor)
  // ==========================================

  async processUploadedFile(
    fileId: string,
    fileType: FileTypeEnum,
  ): Promise<boolean> {
    try {
      const file = await this.fileModel.findById(fileId);
      if (!file) {
        this.logger.error(`File not found: ${fileId}`);
        return false;
      }

      await this.fileModel.findByIdAndUpdate(fileId, {
        status: FileStatus.PROCESSING,
      });

      // Only process images
      if (file.mimetype.startsWith('image/')) {
        // Extract metadata
        await this.extractFileMetadata(fileId);

        // Optimize image
        await this.optimizeImage(fileId);

        // Generate variants if configured
        if (IMAGE_VARIANTS[fileType]) {
          await this.generateImageVariants(fileId, fileType);
        }
      }

      await this.fileModel.findByIdAndUpdate(fileId, {
        status: FileStatus.COMPLETED,
      });

      this.logger.log(`File processed successfully: ${fileId}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to process file ${fileId}:`, error);
      await this.fileModel.findByIdAndUpdate(fileId, {
        status: FileStatus.FAILED,
        errorMessage: error.message,
      });
      return false;
    }
  }

  async extractFileMetadata(fileId: string): Promise<boolean> {
    try {
      const file = await this.fileModel.findById(fileId);
      if (!file) return false;

      if (file.mimetype.startsWith('image/')) {
        const metadata = await sharp(file.path).metadata();

        await this.fileModel.findByIdAndUpdate(fileId, {
          metadata: {
            width: metadata.width,
            height: metadata.height,
            format: metadata.format,
            aspectRatio:
              metadata.width && metadata.height
                ? `${metadata.width}:${metadata.height}`
                : undefined,
          },
        });

        this.logger.debug(`Metadata extracted for file: ${fileId}`);
      }

      return true;
    } catch (error) {
      this.logger.error(`Failed to extract metadata for ${fileId}:`, error);
      return false;
    }
  }

  async optimizeImage(fileId: string): Promise<boolean> {
    try {
      const file = await this.fileModel.findById(fileId);
      if (!file || !file.mimetype.startsWith('image/')) return false;

      const config = IMAGE_OPTIMIZATION[file.type];
      if (!config) return true; // No optimization needed

      const optimizedDir = join(UPLOAD_DIRECTORIES[file.type], 'optimized');

      await fs.mkdir(optimizedDir, { recursive: true });

      const optimizedFilename = `optimized-${file.filename.replace(/\.[^.]+$/, '.webp')}`;
      const optimizedPath = join(optimizedDir, optimizedFilename);

      await sharp(file.path)
        .resize(config.width, config.height, {
          fit: 'inside',
          withoutEnlargement: true,
        })
        .webp({ quality: config.quality })
        .toFile(optimizedPath);

      const stats = await fs.stat(optimizedPath);
      const baseUrl = this.configService.storageBaseUrl;
      const optimizedUrl = `${baseUrl}/${optimizedPath.replace(/\\/g, '/')}`;

      await this.fileModel.findByIdAndUpdate(fileId, {
        optimizedPath,
        optimizedUrl,
        optimizedSize: stats.size,
      });

      this.logger.debug(`Image optimized: ${fileId}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to optimize image ${fileId}:`, error);
      return false;
    }
  }

  async generateImageVariants(
    fileId: string,
    fileType: FileTypeEnum,
  ): Promise<boolean> {
    try {
      const file = await this.fileModel.findById(fileId);
      if (!file || !file.mimetype.startsWith('image/')) return false;

      const variants = IMAGE_VARIANTS[fileType];
      if (!variants) return true;

      const variantsDir = join(UPLOAD_DIRECTORIES[fileType], 'variants');
      await fs.mkdir(variantsDir, { recursive: true });

      const baseUrl = this.configService.storageBaseUrl;
      const variantUrls: string[] = [];

      for (const variant of variants) {
        const variantFilename = `${variant.name}-${file.filename.replace(/\.[^.]+$/, '.webp')}`;
        const variantPath = join(variantsDir, variantFilename);

        await sharp(file.path)
          .resize(variant.width, variant.height, {
            fit: 'cover',
            position: 'center',
          })
          .webp({ quality: 85 })
          .toFile(variantPath);

        const variantUrl = `${baseUrl}/${variantPath.replace(/\\/g, '/')}`;
        variantUrls.push(variantUrl);
      }

      await this.fileModel.findByIdAndUpdate(fileId, {
        variants: variantUrls,
      });

      this.logger.debug(
        `Generated ${variantUrls.length} variants for: ${fileId}`,
      );
      return true;
    } catch (error) {
      this.logger.error(`Failed to generate variants for ${fileId}:`, error);
      return false;
    }
  }

  // ==========================================
  // FILE RETRIEVAL
  // ==========================================

  async findById(fileId: string): Promise<File> {
    const file = await this.fileModel.findById(fileId);
    if (!file) throw new NotFoundException('File not found');
    return file;
  }

  async findByUser(userId: string, page: number = 1, limit: number = 20) {
    const skip = (page - 1) * limit;

    const [files, total] = await Promise.all([
      this.fileModel
        .find({ uploadedBy: userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      this.fileModel.countDocuments({ uploadedBy: userId }),
    ]);

    return {
      files,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  // ==========================================
  // FILE DELETION
  // ==========================================

  async deleteFile(fileId: string, userId: string): Promise<boolean> {
    const file = await this.fileModel.findById(fileId);
    if (!file) throw new NotFoundException('File not found');

    if (file.uploadedBy !== userId) {
      throw new BadRequestException('Unauthorized to delete this file');
    }

    // Queue for deletion
    await this.storageQueueService.deleteFile(fileId);
    return true;
  }

  async deleteFileFromDisk(fileId: string): Promise<boolean> {
    try {
      const file = await this.fileModel.findById(fileId);
      if (!file) return false;

      // Delete original file
      await this.deletePhysicalFile(file.path);

      // Delete optimized version
      if (file.optimizedPath) {
        await this.deletePhysicalFile(file.optimizedPath);
      }

      // Delete variants
      if (file.variants && file.variants.length > 0) {
        const baseUrl = this.configService.storageBaseUrl;
        for (const variantUrl of file.variants) {
          const variantPath = variantUrl.replace(`${baseUrl}/`, '');
          await this.deletePhysicalFile(variantPath);
        }
      }

      // Delete database record
      await this.fileModel.findByIdAndDelete(fileId);

      this.logger.log(`File deleted: ${fileId}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to delete file ${fileId}:`, error);
      return false;
    }
  }

  private async deletePhysicalFile(path: string): Promise<void> {
    try {
      await fs.unlink(path);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        this.logger.error(`Failed to delete physical file ${path}:`, error);
      }
    }
  }

  // ==========================================
  // CLEANUP
  // ==========================================

  async cleanupExpiredFiles(): Promise<boolean> {
    try {
      const expiredFiles = await this.fileModel.find({
        expiresAt: { $lt: new Date() },
      });

      for (const file of expiredFiles) {
        await this.deleteFileFromDisk(file._id.toString());
      }

      this.logger.log(`Cleaned up ${expiredFiles.length} expired files`);
      return true;
    } catch (error) {
      this.logger.error('Failed to cleanup expired files:', error);
      return false;
    }
  }
}
