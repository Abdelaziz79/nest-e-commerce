// src/common/validators/is-real-email.validator.ts
import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

// List of legitimate email provider domains
const LEGITIMATE_EMAIL_DOMAINS = [
  // Major providers
  'gmail.com',
  'yahoo.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'protonmail.com',
  'proton.me',
  'zoho.com',
  'yandex.com',
  'mail.com',
  'gmx.com',
  'gmx.net',

  // Business/Enterprise
  'office365.com',
  'outlook.office365.com',
  'google.com',
  'microsoft.com',
  'apple.com',

  // Regional providers
  'mail.ru',
  'yandex.ru',
  'qq.com',
  '163.com',
  '126.com',
  'sina.com',
  'sohu.com',
  'naver.com',
  'daum.net',
  'hanmail.net',
  'web.de',
  't-online.de',
  'orange.fr',
  'wanadoo.fr',
  'free.fr',
  'laposte.net',
  'libero.it',
  'virgilio.it',
  'tiscali.it',
  'alice.it',
  'tin.it',
  'telenet.be',
  'skynet.be',
  'bluewin.ch',
  'gmx.ch',

  // Educational (common patterns)
  'edu',
  'ac.uk',
  'edu.au',
  'edu.cn',
  'edu.in',
  'edu.sg',

  // Other legitimate providers
  'fastmail.com',
  'tutanota.com',
  'mailfence.com',
  'hushmail.com',
  'posteo.de',
  'mailbox.org',
  'runbox.com',
  'kolabnow.com',
  'startmail.com',
  'ctemplar.com',
];

@ValidatorConstraint({ async: false })
export class IsRealEmailConstraint implements ValidatorConstraintInterface {
  validate(email: any) {
    if (!email || typeof email !== 'string') {
      return false;
    }

    const emailLower = email.toLowerCase();
    const domain = emailLower.split('@')[1];

    if (!domain) {
      return false;
    }

    // Check if it's a legitimate provider
    if (LEGITIMATE_EMAIL_DOMAINS.includes(domain)) {
      return true;
    }

    // Check for educational domains (ends with .edu, .ac.uk, etc.)
    if (
      domain.endsWith('.edu') ||
      domain.endsWith('.ac.uk') ||
      domain.endsWith('.edu.au') ||
      domain.endsWith('.edu.cn') ||
      domain.endsWith('.edu.in') ||
      domain.endsWith('.edu.sg') ||
      domain.endsWith('.ac.in') ||
      domain.endsWith('.ac.jp') ||
      domain.endsWith('.ac.kr')
    ) {
      return true;
    }

    // Check for corporate domains (at least 2 parts and not in common TLDs only)
    const domainParts = domain.split('.');
    if (domainParts.length >= 2) {
      // Allow corporate emails (e.g., john@company.com, jane@startup.io)
      // But reject single-word domains with suspicious TLDs often used by temp mail services
      const tld = domainParts[domainParts.length - 1];
      const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'];

      if (suspiciousTlds.includes(tld) && domainParts.length === 2) {
        return false;
      }

      // If it has a proper structure, allow it
      return true;
    }

    return false;
  }

  defaultMessage() {
    return 'Please use a valid email address from a recognized email provider.';
  }
}

export function IsRealEmail(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsRealEmailConstraint,
    });
  };
}
