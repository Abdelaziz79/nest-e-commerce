// auth/auth.controller.ts

import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { AppConfigService } from 'src/app.config.service';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: AppConfigService,
  ) {}

  // ==========================================
  // GOOGLE
  // ==========================================

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Guards initiates the redirect to Google
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() res) {
    // 1. Generate Tokens for the user returned from strategy
    const tokens = await this.authService.generateTokens(req.user);

    // 2. Add Refresh Token to DB
    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
    );

    // 3. Check if frontend is available, otherwise show success page
    if (this.configService.isDevelopment) {
      // In development, show tokens directly
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
            <h2>✅ Google Authentication Successful!</h2>
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
      // In production, redirect to frontend
      res.redirect(
        `${this.configService.frontendUrl}/social-login?accessToken=${tokens.accessToken}&refreshToken=${tokens.refreshToken}`,
      );
    }
  }

  // ==========================================
  // GITHUB
  // ==========================================

  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth() {
    // Guards initiates the redirect to GitHub
  }

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthRedirect(@Req() req, @Res() res) {
    const tokens = await this.authService.generateTokens(req.user);

    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
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
            <h2>✅ GitHub Authentication Successful!</h2>
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
      res.redirect(
        `${this.configService.frontendUrl}/social-login?accessToken=${tokens.accessToken}&refreshToken=${tokens.refreshToken}`,
      );
    }
  }

  // ==========================================
  // TEST ENDPOINTS (Development Only)
  // ==========================================

  @Get('google/callback/test')
  @UseGuards(AuthGuard('google'))
  async googleAuthTest(@Req() req) {
    // Return JSON instead of redirect for testing
    const tokens = await this.authService.generateTokens(req.user);

    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
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
    // Return JSON instead of redirect for testing
    const tokens = await this.authService.generateTokens(req.user);

    await this.authService['usersService'].addRefreshToken(
      req.user._id.toString(),
      tokens.refreshToken,
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
  // STATUS CHECK ENDPOINT
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
