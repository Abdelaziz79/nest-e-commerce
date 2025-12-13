// auth/strategies/github.strategy.ts

import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { AppConfigService } from 'src/config/app.config.service';
import { AuthService } from '../auth.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(
    configService: AppConfigService,
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

      // FIX 1: Add User-Agent (GitHub requires this)
      userAgent: 'nest-e-commerce-app',
      customHeaders: {
        'User-Agent': 'nest-e-commerce-app',
      },

      // FIX 2: Handle proxy and SSL issues
      proxy: false,
      passReqToCallback: false,

      // FIX 3: Add these important options for API v3
      userProfileURL: 'https://api.github.com/user',

      // FIX 4: Skip certificate verification in development (ONLY for dev)
      ...(configService.isDevelopment && {
        agent: new (require('https').Agent)({
          rejectUnauthorized: false,
        }),
      }),
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: Function,
  ): Promise<any> {
    try {
      const { id, username, displayName, photos, emails } = profile;

      // FIX 5: Better email handling with fallback
      let email: string | null = null;

      if (emails && emails.length > 0) {
        // Find primary email or first verified email
        const primaryEmail = emails.find((e: any) => e.primary && e.verified);
        const verifiedEmail = emails.find((e: any) => e.verified);
        const anyEmail = emails.find((e: any) => e.value);

        email =
          primaryEmail?.value ||
          verifiedEmail?.value ||
          anyEmail?.value ||
          null;
      }

      // FIX 6: If still no email, try fetching from GitHub API directly
      if (!email) {
        try {
          const https = require('https');
          const response = await new Promise<any>((resolve, reject) => {
            https
              .get(
                'https://api.github.com/user/emails',
                {
                  headers: {
                    Authorization: `token ${accessToken}`,
                    'User-Agent': 'nest-e-commerce-app',
                  },
                },
                (res: any) => {
                  let data = '';
                  res.on('data', (chunk: any) => (data += chunk));
                  res.on('end', () => {
                    try {
                      resolve(JSON.parse(data));
                    } catch (e) {
                      reject(e);
                    }
                  });
                },
              )
              .on('error', reject);
          });

          if (Array.isArray(response)) {
            const primaryEmail = response.find(
              (e: any) => e.primary && e.verified,
            );
            const verifiedEmail = response.find((e: any) => e.verified);
            email =
              primaryEmail?.email ||
              verifiedEmail?.email ||
              response[0]?.email ||
              null;
          }
        } catch (apiError) {
          console.error('Failed to fetch emails from GitHub API:', apiError);
        }
      }

      // If no email found, we can't proceed
      if (!email) {
        console.error('GitHub Auth Error: No email provided by GitHub');
        return done(
          new Error(
            'No email provided by GitHub. Please make sure your GitHub email is verified and public.',
          ),
          null,
        );
      }

      // FIX 7: Better name handling
      const firstName = displayName?.split(' ')[0] || username || 'GitHub';
      const lastName = displayName?.split(' ').slice(1).join(' ') || 'User';
      const picture = photos && photos.length > 0 ? photos[0].value : null;

      const user = await this.authService.validateSocialUser({
        socialId: id,
        email: email,
        firstName: firstName,
        lastName: lastName,
        picture: picture,
        provider: 'github',
      });

      done(null, user);
    } catch (error) {
      console.error('GitHub Strategy Error:', error);
      done(error, null);
    }
  }
}
