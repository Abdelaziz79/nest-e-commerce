// src/notifications/notification-helper.service.ts

import { Injectable, Logger } from '@nestjs/common';
import { NotificationType } from './schemas/notification.schema';
import { NotificationTemplatesService } from './notification-templates.service';
import { NotificationsService } from './notifications.service';

/**
 * Helper service for easy notification creation throughout the app
 * This is what other modules will use to send notifications
 */
@Injectable()
export class NotificationHelperService {
  private readonly logger = new Logger(NotificationHelperService.name);

  constructor(
    private readonly notificationsService: NotificationsService,
    private readonly templatesService: NotificationTemplatesService,
  ) {}

  // ==========================================
  // ORDER NOTIFICATIONS
  // ==========================================

  async notifyOrderPlaced(
    userId: string,
    orderData: {
      orderId: string;
      total: number;
    },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.ORDER_PLACED,
      orderData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.ORDER_PLACED,
      ...template,
    });
  }

  async notifyOrderConfirmed(userId: string, orderData: { orderId: string }) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.ORDER_CONFIRMED,
      orderData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.ORDER_CONFIRMED,
      ...template,
    });
  }

  async notifyOrderShipped(
    userId: string,
    orderData: { orderId: string; trackingNumber?: string },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.ORDER_SHIPPED,
      orderData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.ORDER_SHIPPED,
      ...template,
    });
  }

  async notifyOrderDelivered(userId: string, orderData: { orderId: string }) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.ORDER_DELIVERED,
      orderData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.ORDER_DELIVERED,
      ...template,
    });
  }

  async notifyOrderCancelled(
    userId: string,
    orderData: { orderId: string; reason?: string },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.ORDER_CANCELLED,
      orderData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.ORDER_CANCELLED,
      ...template,
    });
  }

  // ==========================================
  // PAYMENT NOTIFICATIONS
  // ==========================================

  async notifyPaymentSuccess(
    userId: string,
    paymentData: { orderId: string; amount: number },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.PAYMENT_SUCCESS,
      paymentData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.PAYMENT_SUCCESS,
      ...template,
    });
  }

  async notifyPaymentFailed(
    userId: string,
    paymentData: { orderId: string; amount: number; reason?: string },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.PAYMENT_FAILED,
      paymentData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.PAYMENT_FAILED,
      ...template,
    });
  }

  // ==========================================
  // PRODUCT NOTIFICATIONS
  // ==========================================

  async notifyProductBackInStock(
    userId: string,
    productData: { productId: string; productName: string },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.PRODUCT_BACK_IN_STOCK,
      productData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.PRODUCT_BACK_IN_STOCK,
      ...template,
    });
  }

  async notifyPriceDrop(
    userId: string,
    productData: {
      productId: string;
      productName: string;
      oldPrice: number;
      newPrice: number;
      discount: number;
    },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.PRICE_DROP,
      productData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.PRICE_DROP,
      ...template,
    });
  }

  async notifyWishlistItemSale(
    userId: string,
    productData: {
      productId: string;
      productName: string;
      discount: number;
    },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.WISHLIST_ITEM_SALE,
      productData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.WISHLIST_ITEM_SALE,
      ...template,
    });
  }

  // ==========================================
  // ACCOUNT NOTIFICATIONS
  // ==========================================

  async notifyAccountSecurity(
    userId: string,
    securityData: { message: string },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.ACCOUNT_SECURITY,
      securityData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.ACCOUNT_SECURITY,
      ...template,
    });
  }

  async notifyTwoFactorEnabled(userId: string) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.TWO_FACTOR_ENABLED,
      {},
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.TWO_FACTOR_ENABLED,
      ...template,
    });
  }

  async notifyPasswordChanged(userId: string) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.PASSWORD_CHANGED,
      {},
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.PASSWORD_CHANGED,
      ...template,
    });
  }

  async notifyEmailVerified(userId: string) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.EMAIL_VERIFIED,
      {},
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.EMAIL_VERIFIED,
      ...template,
    });
  }

  async notifyWelcome(
    userId: string,
    userData: { firstName: string; appName: string },
  ) {
    const template = this.templatesService.createFromTemplate(
      NotificationType.WELCOME,
      userData,
    );

    return this.notificationsService.createNotification(userId, {
      type: NotificationType.WELCOME,
      ...template,
    });
  }

  // ==========================================
  // BULK NOTIFICATIONS
  // ==========================================

  async notifyMultipleUsers(
    userIds: string[],
    type: NotificationType,
    data: Record<string, any>,
  ) {
    const template = this.templatesService.createFromTemplate(type, data);

    return this.notificationsService.createBulkNotifications({
      userIds,
      type,
      ...template,
    });
  }
}
