// src/common/interceptors/audit-log.interceptor.ts

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { AUDIT_LOG_KEY } from '../decorators/audit-log.decorator';

@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  private readonly logger = new Logger('AuditLog');

  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const action = this.reflector.get<string>(
      AUDIT_LOG_KEY,
      context.getHandler(),
    );

    if (!action) {
      return next.handle();
    }

    const ctx = GqlExecutionContext.create(context);
    const { req } = ctx.getContext();
    const user = req.user;
    const info = ctx.getInfo();

    return next.handle().pipe(
      tap((result) => {
        this.logger.log(
          JSON.stringify({
            action,
            userId: user?._id?.toString(),
            userEmail: user?.email,
            operation: info?.fieldName,
            timestamp: new Date().toISOString(),
            ip: req.ip,
            userAgent: req.get('user-agent'),
          }),
        );
      }),
    );
  }
}
