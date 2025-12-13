// auth/auth.controller.ts

import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AppConfigService } from 'src/config/app.config.service';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: AppConfigService,
  ) {}

  // ==========================================
  // GOOGLE OAUTH
  // ==========================================

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Initiates redirect to Google
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() res) {
    const tokens = await this.authService.generateTokens(req.user);

    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
      'Google OAuth',
    );

    if (this.configService.isDevelopment) {
      // Development: Show tokens on page
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Google Login Success</title>
          <style>
            body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
            .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 5px; }
            .token { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; word-break: break-all; }
            h2 { color: #155724; }
            code { background: #fff; padding: 5px; border: 1px solid #ddd; }
          </style>
        </head>
        <body>
          <div class="success">
            <h2>Google Authentication Successful!</h2>
            <p><strong>User:</strong> ${req.user.email}</p>
            <p><strong>Name:</strong> ${req.user.firstName} ${req.user.lastName}</p>
            <p><strong>User ID:</strong> ${req.user._id}</p>
            
            <h3>Access Token:</h3>
            <div class="token"><code>${tokens.accessToken}</code></div>
            
            <h3>Refresh Token:</h3>
            <div class="token"><code>${tokens.refreshToken}</code></div>
            
            <p><small>Copy these tokens to use in your GraphQL requests with Authorization header: Bearer [accessToken]</small></p>
          </div>
        </body>
        </html>
      `);
    } else {
      // Production: Use HTTP-Only cookies + secure redirect
      const isProduction = this.configService.environment === 'production';

      // Set HTTP-Only cookies (more secure than URL params)
      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: isProduction, // HTTPS only in production
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes
        path: '/',
      });

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/',
      });

      // Redirect to frontend success page
      // Frontend will read tokens from cookies via API call
      res.redirect(`${this.configService.frontendUrl}/auth/success`);
    }
  }

  // ==========================================
  // GITHUB OAUTH
  // ==========================================

  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth() {
    // Initiates redirect to GitHub
  }

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthRedirect(@Req() req, @Res() res) {
    const tokens = await this.authService.generateTokens(req.user);

    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
      'GitHub OAuth',
    );

    if (this.configService.isDevelopment) {
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>GitHub Login Success</title>
          <style>
            body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
            .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 5px; }
            .token { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; word-break: break-all; }
            h2 { color: #155724; }
            code { background: #fff; padding: 5px; border: 1px solid #ddd; }
          </style>
        </head>
        <body>
          <div class="success">
            <h2>GitHub Authentication Successful!</h2>
            <p><strong>User:</strong> ${req.user.email || 'N/A'}</p>
            <p><strong>Name:</strong> ${req.user.firstName} ${req.user.lastName}</p>
            <p><strong>User ID:</strong> ${req.user._id}</p>
            
            <h3>Access Token:</h3>
            <div class="token"><code>${tokens.accessToken}</code></div>
            
            <h3>Refresh Token:</h3>
            <div class="token"><code>${tokens.refreshToken}</code></div>
            
            <p><small>Copy these tokens to use in your GraphQL requests with Authorization header: Bearer [accessToken]</small></p>
          </div>
        </body>
        </html>
      `);
    } else {
      const isProduction = this.configService.environment === 'production';

      res.cookie('accessToken', tokens.accessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000,
        path: '/',
      });

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/',
      });

      res.redirect(`${this.configService.frontendUrl}/auth/success`);
    }
  }

  // ==========================================
  // TOKEN RETRIEVAL (for frontend after OAuth)
  // ==========================================

  /**
   * Frontend calls this after OAuth redirect to get tokens from cookies
   * Then stores them in localStorage/memory
   */
  @Get('tokens')
  @UseGuards(AuthGuard('jwt'))
  async getTokens(@Req() req: Request & { user: any }, @Res() res) {
    const accessToken = req.cookies?.accessToken;
    const refreshToken = req.cookies?.refreshToken;

    if (!accessToken || !refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'No tokens found',
      });
    }

    // Clear cookies after reading
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    // Return tokens to frontend
    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: req.user.id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        role: req.user.role,
      },
    });
  }

  // ==========================================
  // TEST ENDPOINTS (Development Only)
  // ==========================================

  @Get('google/callback/test')
  @UseGuards(AuthGuard('google'))
  async googleAuthTest(@Req() req) {
    const tokens = await this.authService.generateTokens(req.user);

    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
      'Google OAuth Test',
    );

    return {
      success: true,
      message: 'Google authentication successful',
      user: {
        id: req.user._id.toString(),
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
      },
      tokens,
    };
  }

  @Get('github/callback/test')
  @UseGuards(AuthGuard('github'))
  async githubAuthTest(@Req() req) {
    const tokens = await this.authService.generateTokens(req.user);

    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
      'GitHub OAuth Test',
    );

    return {
      success: true,
      message: 'GitHub authentication successful',
      user: {
        id: req.user._id.toString(),
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
      },
      tokens,
    };
  }

  // ==========================================
  // STATUS CHECK
  // ==========================================

  @Get('status')
  async checkAuthStatus() {
    return {
      google: {
        configured: !!(
          this.configService.googleClientId &&
          this.configService.googleClientSecret
        ),
        callbackUrl: this.configService.googleCallbackUrl,
      },
      github: {
        configured: !!(
          this.configService.githubClientId &&
          this.configService.githubClientSecret
        ),
        callbackUrl: this.configService.githubCallbackUrl,
      },
      frontendUrl: this.configService.frontendUrl,
    };
  }
}
