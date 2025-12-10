// src/storage/storage.resolver.ts
import { UseGuards } from '@nestjs/common';
import { Args, ID, Mutation, Query, Resolver } from '@nestjs/graphql';
import { createWriteStream, promises as fs } from 'fs';
import type { FileUpload } from 'graphql-upload-ts';
import { GraphQLUpload } from 'graphql-upload-ts';
import { join } from 'path';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { GqlAuthGuard } from '../auth/guards/gql-auth.guard';
import { User } from '../users/schemas/user.schema';
import { UPLOAD_DIRECTORIES } from './config/multer.config';
import {
  FileType as FileTypeGQL,
  PaginatedFilesType,
  UploadResponse,
} from './dto/file.types';
import { FileTypeEnum } from './schemas/file.schema';
import { StorageService } from './storage.service';

@Resolver(() => FileTypeGQL)
export class StorageResolver {
  constructor(private readonly storageService: StorageService) {}

  // ==========================================
  // UPLOAD MUTATION
  // ==========================================

  @Mutation(() => UploadResponse)
  @UseGuards(GqlAuthGuard)
  async uploadFile(
    @Args({ name: 'file', type: () => GraphQLUpload })
    fileUpload: FileUpload,
    @Args('fileType', { type: () => FileTypeEnum }) fileType: FileTypeEnum,
    @Args('relatedEntity', { type: () => String, nullable: true })
    relatedEntity: string | undefined,
    @Args('relatedEntityId', { type: () => String, nullable: true })
    relatedEntityId: string | undefined,
    @CurrentUser()
    user: User,
  ): Promise<UploadResponse> {
    try {
      const { createReadStream, filename, mimetype } = await fileUpload;

      // Ensure upload directory exists
      const uploadDir = UPLOAD_DIRECTORIES[fileType];
      await fs.mkdir(uploadDir, { recursive: true });

      // Generate unique filename
      const uniqueFilename = `${Date.now()}-${filename}`;
      const filePath = join(uploadDir, uniqueFilename);

      // Save file to disk
      const stream = createReadStream();
      const writeStream = createWriteStream(filePath);

      await new Promise((resolve, reject) => {
        stream.pipe(writeStream);
        writeStream.on('finish', () => resolve(true));
        writeStream.on('error', reject);
      });

      // Get file stats
      const stats = await fs.stat(filePath);

      // Create file record with Express.Multer.File compatible object
      const multerFile = {
        fieldname: 'file',
        originalname: filename,
        encoding: '7bit',
        mimetype,
        destination: uploadDir,
        filename: uniqueFilename,
        path: filePath,
        size: stats.size,
      } as Express.Multer.File;

      const file = await this.storageService.createFileRecord(
        multerFile,
        fileType,
        user._id.toString(),
        {
          relatedEntity,
          relatedEntityId,
          isPublic: true,
        },
      );

      return {
        success: true,
        message: 'File uploaded successfully and queued for processing',
        file: file as any,
      };
    } catch (error) {
      return {
        success: false,
        message: error.message || 'Failed to upload file',
        file: null,
      };
    }
  }

  // ==========================================
  // QUERIES
  // ==========================================

  @Query(() => FileTypeGQL)
  @UseGuards(GqlAuthGuard)
  async file(@Args('id', { type: () => ID }) id: string) {
    return this.storageService.findById(id);
  }

  @Query(() => PaginatedFilesType)
  @UseGuards(GqlAuthGuard)
  async myFiles(
    @CurrentUser() user: User,
    @Args('page', { type: () => Number, nullable: true, defaultValue: 1 })
    page?: number,
    @Args('limit', { type: () => Number, nullable: true, defaultValue: 20 })
    limit?: number,
  ) {
    return this.storageService.findByUser(user._id.toString(), page, limit);
  }

  // ==========================================
  // MUTATIONS
  // ==========================================

  @Mutation(() => Boolean)
  @UseGuards(GqlAuthGuard)
  async deleteFile(
    @Args('id', { type: () => ID }) id: string,
    @CurrentUser() user: User,
  ) {
    return this.storageService.deleteFile(id, user._id.toString());
  }
}
