// auth/strategies/github.strategy.ts

import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { AppConfigService } from 'src/app.config.service';
import { AuthService } from '../auth.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(
    private readonly configService: AppConfigService,
    private readonly authService: AuthService,
  ) {
    const clientID = configService.githubClientId;
    const clientSecret = configService.githubClientSecret;
    const callbackURL = configService.githubCallbackUrl;

    if (!clientID || !clientSecret || !callbackURL) {
      throw new Error('GitHub OAuth configuration is missing');
    }

    super({
      clientID,
      clientSecret,
      callbackURL,
      scope: ['user:email'], // Request email access
      // ✅ FIX: GitHub requires User-Agent header (mandatory since 2014)
      userAgent: 'nest-e-commerce-app',
      customHeaders: {
        'User-Agent': 'nest-e-commerce-app',
      },
      // ✅ FIX: Add these options to handle SSL/proxy issues
      proxy: false,
      passReqToCallback: false,
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: Function,
  ): Promise<any> {
    try {
      const { id, username, photos, emails } = profile;

      // GitHub emails can be tricky - handle various cases
      let email: string | null = null;

      if (emails && emails.length > 0) {
        // Find primary email or first verified email
        const primaryEmail = emails.find((e: any) => e.primary && e.verified);
        const verifiedEmail = emails.find((e: any) => e.verified);
        email = primaryEmail?.value || verifiedEmail?.value || emails[0].value;
      }

      // If no email found, we can't proceed
      if (!email) {
        console.error('GitHub Auth Error: No email provided by GitHub');
        return done(
          new Error(
            'No email provided by GitHub. Please ensure your email is verified on GitHub.',
          ),
          null,
        );
      }

      const user = await this.authService.validateSocialUser({
        socialId: id,
        email: email,
        firstName: username || 'GitHub',
        lastName: 'User', // GitHub doesn't always provide names split
        picture: photos && photos.length > 0 ? photos[0].value : null,
        provider: 'github',
      });

      done(null, user);
    } catch (error) {
      console.error('GitHub Strategy Error:', error);
      done(error, null);
    }
  }
}
