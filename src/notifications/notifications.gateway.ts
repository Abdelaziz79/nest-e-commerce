// src/notifications/notifications.gateway.ts

import { Logger, UseGuards } from '@nestjs/common';
import {
  ConnectedSocket,
  MessageBody,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { AppConfigService } from 'src/config/app.config.service';
import { WsJwtGuard } from './guards/ws-jwt.guard';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  user?: any;
}

@WebSocketGateway({
  cors: {
    origin: '*', // This will be properly configured in constructor
    credentials: true,
  },
  namespace: 'notifications',
})
export class NotificationsGateway
  implements OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(NotificationsGateway.name);
  private readonly connectedUsers = new Map<string, Set<string>>();

  constructor(private readonly configService: AppConfigService) {
    this.logger.log('NotificationsGateway initialized');
  }

  // Configure CORS after initialization
  afterInit(server: Server) {
    server.on('connection', (socket) => {
      const origin = socket.handshake.headers.origin;
      const allowedOrigin = this.configService.corsOrigin;

      if (
        origin !== allowedOrigin &&
        this.configService.isDevelopment === false
      ) {
        this.logger.warn(`Rejected connection from origin: ${origin}`);
        socket.disconnect();
      }
    });
  }

  // ==========================================
  // CONNECTION HANDLING
  // ==========================================

  async handleConnection(client: AuthenticatedSocket) {
    try {
      const token =
        client.handshake.auth?.token ||
        client.handshake.headers?.authorization?.replace('Bearer ', '');

      if (!token) {
        this.logger.warn(
          `Client ${client.id} connection rejected: No token provided`,
        );
        client.disconnect();
        return;
      }

      this.logger.log(`Client connected: ${client.id}`);
    } catch (error) {
      this.logger.error(`Connection error: ${error.message}`);
      client.disconnect();
    }
  }

  handleDisconnect(client: AuthenticatedSocket) {
    if (client.userId) {
      const userSockets = this.connectedUsers.get(client.userId);
      if (userSockets) {
        userSockets.delete(client.id);
        if (userSockets.size === 0) {
          this.connectedUsers.delete(client.userId);
        }
      }
    }

    this.logger.log(`Client disconnected: ${client.id}`);
  }

  // ==========================================
  // SUBSCRIPTION HANDLERS
  // ==========================================

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('subscribe')
  handleSubscribe(
    @ConnectedSocket() client: AuthenticatedSocket,
    @MessageBody() data: { userId: string },
  ) {
    const { userId } = data;

    if (!userId) {
      client.emit('error', { message: 'User ID is required' });
      return;
    }

    if (!this.connectedUsers.has(userId)) {
      this.connectedUsers.set(userId, new Set());
    }
    const userSockets = this.connectedUsers.get(userId);
    if (userSockets) {
      userSockets.add(client.id);
    }

    client.userId = userId;

    this.logger.log(`User ${userId} subscribed with socket ${client.id}`);
    client.emit('subscribed', {
      message: 'Successfully subscribed to notifications',
      userId,
    });
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('unsubscribe')
  handleUnsubscribe(@ConnectedSocket() client: AuthenticatedSocket) {
    if (client.userId) {
      const userSockets = this.connectedUsers.get(client.userId);
      if (userSockets) {
        userSockets.delete(client.id);
        if (userSockets.size === 0) {
          this.connectedUsers.delete(client.userId);
        }
      }
    }

    this.logger.log(`Client ${client.id} unsubscribed`);
    client.emit('unsubscribed', { message: 'Successfully unsubscribed' });
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('ping')
  handlePing(@ConnectedSocket() client: AuthenticatedSocket) {
    client.emit('pong', { timestamp: new Date().toISOString() });
  }

  // ==========================================
  // SEND NOTIFICATIONS
  // ==========================================

  sendToUser(userId: string, event: string, data: any) {
    const userSockets = this.connectedUsers.get(userId);

    if (!userSockets || userSockets.size === 0) {
      this.logger.debug(
        `User ${userId} not connected, skipping real-time notification`,
      );
      return;
    }

    userSockets.forEach((socketId) => {
      this.server.to(socketId).emit(event, data);
    });

    this.logger.debug(
      `Sent ${event} to user ${userId} (${userSockets.size} devices)`,
    );
  }

  sendToUsers(userIds: string[], event: string, data: any) {
    userIds.forEach((userId) => {
      this.sendToUser(userId, event, data);
    });
  }

  broadcastToAll(event: string, data: any) {
    this.server.emit(event, data);
    this.logger.log(`Broadcasted ${event} to all connected users`);
  }

  getConnectedUsersCount(): number {
    return this.connectedUsers.size;
  }

  isUserConnected(userId: string): boolean {
    return this.connectedUsers.has(userId);
  }

  getUserSocketCount(userId: string): number {
    return this.connectedUsers.get(userId)?.size || 0;
  }
}
