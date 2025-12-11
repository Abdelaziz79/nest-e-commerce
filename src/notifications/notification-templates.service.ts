// src/notifications/notification-templates.service.ts

import { Injectable } from '@nestjs/common';
import {
  NotificationChannel,
  NotificationPriority,
  NotificationType,
} from './schemas/notification.schema';

export interface NotificationTemplate {
  type: NotificationType;
  title: string;
  message: string;
  priority: NotificationPriority;
  channels: NotificationChannel[];
  actionUrl?: string;
  actionText?: string;
  icon?: string;
}

@Injectable()
export class NotificationTemplatesService {
  /**
   * Get notification template with dynamic data
   */
  getTemplate(
    type: NotificationType,
    data: Record<string, any>,
  ): NotificationTemplate {
    const templates: Record<
      NotificationType,
      (data: any) => NotificationTemplate
    > = {
      // ==========================================
      // ORDER NOTIFICATIONS
      // ==========================================
      [NotificationType.ORDER_PLACED]: (data) => ({
        type: NotificationType.ORDER_PLACED,
        title: 'Order Placed Successfully! 🎉',
        message: `Your order #${data.orderId} has been placed successfully. Total: $${data.total}`,
        priority: NotificationPriority.HIGH,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/orders/${data.orderId}`,
        actionText: 'View Order',
        icon: '🛍️',
      }),

      [NotificationType.ORDER_CONFIRMED]: (data) => ({
        type: NotificationType.ORDER_CONFIRMED,
        title: 'Order Confirmed ✅',
        message: `Your order #${data.orderId} has been confirmed and is being prepared.`,
        priority: NotificationPriority.NORMAL,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/orders/${data.orderId}`,
        actionText: 'Track Order',
        icon: '✅',
      }),

      [NotificationType.ORDER_SHIPPED]: (data) => ({
        type: NotificationType.ORDER_SHIPPED,
        title: 'Order Shipped! 📦',
        message: `Your order #${data.orderId} has been shipped. ${data.trackingNumber ? `Tracking: ${data.trackingNumber}` : ''}`,
        priority: NotificationPriority.HIGH,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/orders/${data.orderId}/tracking`,
        actionText: 'Track Package',
        icon: '📦',
      }),

      [NotificationType.ORDER_DELIVERED]: (data) => ({
        type: NotificationType.ORDER_DELIVERED,
        title: 'Order Delivered! 🎁',
        message: `Your order #${data.orderId} has been delivered. Enjoy your purchase!`,
        priority: NotificationPriority.NORMAL,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/orders/${data.orderId}`,
        actionText: 'Leave a Review',
        icon: '🎁',
      }),

      [NotificationType.ORDER_CANCELLED]: (data) => ({
        type: NotificationType.ORDER_CANCELLED,
        title: 'Order Cancelled',
        message: `Your order #${data.orderId} has been cancelled. ${data.reason || 'Refund will be processed within 5-7 business days.'}`,
        priority: NotificationPriority.HIGH,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/orders/${data.orderId}`,
        actionText: 'View Details',
        icon: '❌',
      }),

      // ==========================================
      // PAYMENT NOTIFICATIONS
      // ==========================================
      [NotificationType.PAYMENT_SUCCESS]: (data) => ({
        type: NotificationType.PAYMENT_SUCCESS,
        title: 'Payment Successful ✅',
        message: `Payment of $${data.amount} for order #${data.orderId} was successful.`,
        priority: NotificationPriority.HIGH,
        channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL],
        actionUrl: `/orders/${data.orderId}`,
        actionText: 'View Order',
        icon: '💳',
      }),

      [NotificationType.PAYMENT_FAILED]: (data) => ({
        type: NotificationType.PAYMENT_FAILED,
        title: 'Payment Failed ⚠️',
        message: `Payment of $${data.amount} for order #${data.orderId} failed. ${data.reason || 'Please try again or use a different payment method.'}`,
        priority: NotificationPriority.URGENT,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/orders/${data.orderId}/payment`,
        actionText: 'Retry Payment',
        icon: '⚠️',
      }),

      // ==========================================
      // PRODUCT NOTIFICATIONS
      // ==========================================
      [NotificationType.PRODUCT_BACK_IN_STOCK]: (data) => ({
        type: NotificationType.PRODUCT_BACK_IN_STOCK,
        title: 'Back in Stock! 🎉',
        message: `${data.productName} is now back in stock. Get it before it's gone!`,
        priority: NotificationPriority.NORMAL,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/products/${data.productId}`,
        actionText: 'Shop Now',
        icon: '🛒',
      }),

      [NotificationType.PRICE_DROP]: (data) => ({
        type: NotificationType.PRICE_DROP,
        title: 'Price Drop Alert! 💰',
        message: `${data.productName} is now ${data.discount}% off! Was $${data.oldPrice}, now $${data.newPrice}`,
        priority: NotificationPriority.NORMAL,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/products/${data.productId}`,
        actionText: 'View Deal',
        icon: '🏷️',
      }),

      [NotificationType.WISHLIST_ITEM_SALE]: (data) => ({
        type: NotificationType.WISHLIST_ITEM_SALE,
        title: 'Wishlist Item on Sale! 🎁',
        message: `${data.productName} from your wishlist is now on sale! Save ${data.discount}%`,
        priority: NotificationPriority.NORMAL,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: `/products/${data.productId}`,
        actionText: 'Buy Now',
        icon: '❤️',
      }),

      // ==========================================
      // SOCIAL NOTIFICATIONS
      // ==========================================
      [NotificationType.REVIEW_REPLY]: (data) => ({
        type: NotificationType.REVIEW_REPLY,
        title: 'New Reply to Your Review 💬',
        message: `${data.userName} replied to your review on ${data.productName}`,
        priority: NotificationPriority.LOW,
        channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL],
        actionUrl: `/products/${data.productId}#reviews`,
        actionText: 'View Reply',
        icon: '💬',
      }),

      // ==========================================
      // ACCOUNT NOTIFICATIONS
      // ==========================================
      [NotificationType.ACCOUNT_SECURITY]: (data) => ({
        type: NotificationType.ACCOUNT_SECURITY,
        title: 'Security Alert 🔒',
        message: data.message,
        priority: NotificationPriority.URGENT,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: '/account/security',
        actionText: 'Review Activity',
        icon: '🔒',
      }),

      [NotificationType.TWO_FACTOR_ENABLED]: (data) => ({
        type: NotificationType.TWO_FACTOR_ENABLED,
        title: 'Two-Factor Authentication Enabled ✅',
        message:
          'Two-factor authentication has been successfully enabled on your account.',
        priority: NotificationPriority.NORMAL,
        channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL],
        actionUrl: '/account/security',
        actionText: 'View Settings',
        icon: '🔐',
      }),

      [NotificationType.PASSWORD_CHANGED]: (data) => ({
        type: NotificationType.PASSWORD_CHANGED,
        title: 'Password Changed ✅',
        message:
          "Your password has been successfully changed. If this wasn't you, please contact support immediately.",
        priority: NotificationPriority.HIGH,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: '/account/security',
        actionText: 'Review Activity',
        icon: '🔑',
      }),

      [NotificationType.EMAIL_VERIFIED]: (data) => ({
        type: NotificationType.EMAIL_VERIFIED,
        title: 'Email Verified! ✅',
        message:
          'Your email has been successfully verified. You can now access all features.',
        priority: NotificationPriority.NORMAL,
        channels: [NotificationChannel.IN_APP],
        actionUrl: '/dashboard',
        actionText: 'Go to Dashboard',
        icon: '✉️',
      }),

      [NotificationType.WELCOME]: (data) => ({
        type: NotificationType.WELCOME,
        title: `Welcome to ${data.appName}! 🎉`,
        message: `Hi ${data.firstName}! We're excited to have you. Start exploring our amazing products!`,
        priority: NotificationPriority.NORMAL,
        channels: [NotificationChannel.IN_APP],
        actionUrl: '/products',
        actionText: 'Start Shopping',
        icon: '👋',
      }),

      // ==========================================
      // SYSTEM NOTIFICATIONS
      // ==========================================
      [NotificationType.PROMOTIONAL]: (data) => ({
        type: NotificationType.PROMOTIONAL,
        title: data.title || 'Special Offer! 🎁',
        message: data.message,
        priority: NotificationPriority.LOW,
        channels: [
          NotificationChannel.IN_APP,
          NotificationChannel.EMAIL,
          NotificationChannel.PUSH,
        ],
        actionUrl: data.actionUrl || '/promotions',
        actionText: data.actionText || 'Learn More',
        icon: '🎁',
      }),

      [NotificationType.SYSTEM]: (data) => ({
        type: NotificationType.SYSTEM,
        title: data.title || 'System Notification',
        message: data.message,
        priority: data.priority || NotificationPriority.NORMAL,
        channels: [NotificationChannel.IN_APP],
        actionUrl: data.actionUrl,
        actionText: data.actionText,
        icon: '⚙️',
      }),

      [NotificationType.ADMIN_MESSAGE]: (data) => ({
        type: NotificationType.ADMIN_MESSAGE,
        title: data.title || 'Message from Admin',
        message: data.message,
        priority: NotificationPriority.HIGH,
        channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL],
        actionUrl: data.actionUrl,
        actionText: data.actionText,
        icon: '👤',
      }),
    };

    const templateFn = templates[type];
    if (!templateFn) {
      throw new Error(`No template found for notification type: ${type}`);
    }

    return templateFn(data);
  }

  /**
   * Helper method to create notification from template
   */
  createFromTemplate(
    type: NotificationType,
    data: Record<string, any>,
  ): Omit<NotificationTemplate, 'type'> {
    const template = this.getTemplate(type, data);
    return {
      title: template.title,
      message: template.message,
      priority: template.priority,
      channels: template.channels,
      actionUrl: template.actionUrl,
      actionText: template.actionText,
      icon: template.icon,
    };
  }
}
