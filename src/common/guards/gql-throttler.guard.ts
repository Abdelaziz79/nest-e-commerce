// common/guards/gql-throttler.guard.ts

import { ExecutionContext, Injectable } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class GqlThrottlerGuard extends ThrottlerGuard {
  getRequestResponse(context: ExecutionContext) {
    // Check if this is an HTTP context (REST endpoint)
    const contextType = context.getType();

    if (contextType === 'http') {
      // For REST endpoints, use standard HTTP context
      const http = context.switchToHttp();
      return { req: http.getRequest(), res: http.getResponse() };
    }

    // For GraphQL endpoints, convert to GraphQL context
    const gqlCtx = GqlExecutionContext.create(context);
    const ctx = gqlCtx.getContext();

    return { req: ctx.req, res: ctx.res };
  }
}
