// src/mail/mail.module.ts
import { Module } from '@nestjs/common';
import { AppConfigModule } from 'src/app.config.module';
import { MailService } from './mail.service';

@Module({
  imports: [AppConfigModule],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
