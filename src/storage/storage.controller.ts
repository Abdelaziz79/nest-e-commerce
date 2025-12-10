// src/storage/storage.controller.ts
import {
  Controller,
  Post,
  UseGuards,
  UploadedFile,
  UseInterceptors,
  Body,
  Get,
  Param,
  Delete,
  Req,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { AuthGuard } from '@nestjs/passport';
import { StorageService } from './storage.service';
import { FileTypeEnum } from './schemas/file.schema';
import { getMulterOptions } from './config/multer.config';

@Controller('storage')
export class StorageController {
  constructor(private readonly storageService: StorageService) {}

  // ==========================================
  // REST UPLOAD ENDPOINTS (for direct uploads)
  // ==========================================

  @Post('upload/avatar')
  @UseGuards(AuthGuard('jwt'))
  @UseInterceptors(
    FileInterceptor('file', getMulterOptions(FileTypeEnum.AVATAR)),
  )
  async uploadAvatar(
    @UploadedFile() file: Express.Multer.File,
    @Req() req: any,
  ) {
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }

    const fileRecord = await this.storageService.createFileRecord(
      file,
      FileTypeEnum.AVATAR,
      req.user._id.toString(),
      { isPublic: true },
    );

    return {
      success: true,
      message: 'Avatar uploaded successfully',
      file: {
        id: fileRecord._id,
        url: fileRecord.url,
        filename: fileRecord.filename,
      },
    };
  }

  @Post('upload/product')
  @UseGuards(AuthGuard('jwt'))
  @UseInterceptors(
    FileInterceptor('file', getMulterOptions(FileTypeEnum.PRODUCT_IMAGE)),
  )
  async uploadProductImage(
    @UploadedFile() file: Express.Multer.File,
    @Body('productId') productId: string,
    @Req() req: any,
  ) {
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }

    const fileRecord = await this.storageService.createFileRecord(
      file,
      FileTypeEnum.PRODUCT_IMAGE,
      req.user._id.toString(),
      {
        relatedEntity: 'product',
        relatedEntityId: productId,
        isPublic: true,
      },
    );

    return {
      success: true,
      message: 'Product image uploaded successfully',
      file: {
        id: fileRecord._id,
        url: fileRecord.url,
        optimizedUrl: fileRecord.optimizedUrl,
        variants: fileRecord.variants,
      },
    };
  }

  @Post('upload/document')
  @UseGuards(AuthGuard('jwt'))
  @UseInterceptors(
    FileInterceptor('file', getMulterOptions(FileTypeEnum.DOCUMENT)),
  )
  async uploadDocument(
    @UploadedFile() file: Express.Multer.File,
    @Req() req: any,
  ) {
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }

    const fileRecord = await this.storageService.createFileRecord(
      file,
      FileTypeEnum.DOCUMENT,
      req.user._id.toString(),
      { isPublic: false },
    );

    return {
      success: true,
      message: 'Document uploaded successfully',
      file: {
        id: fileRecord._id,
        url: fileRecord.url,
        filename: fileRecord.filename,
      },
    };
  }

  // ==========================================
  // FILE MANAGEMENT
  // ==========================================

  @Get('file/:id')
  @UseGuards(AuthGuard('jwt'))
  async getFile(@Param('id') id: string) {
    return this.storageService.findById(id);
  }

  @Get('my-files')
  @UseGuards(AuthGuard('jwt'))
  async getMyFiles(@Req() req: any) {
    return this.storageService.findByUser(req.user._id.toString());
  }

  @Delete('file/:id')
  @UseGuards(AuthGuard('jwt'))
  async deleteFile(@Param('id') id: string, @Req() req: any) {
    await this.storageService.deleteFile(id, req.user._id.toString());
    return { success: true, message: 'File deleted successfully' };
  }
}
