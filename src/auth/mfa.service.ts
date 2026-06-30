import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { MailService } from '../mail/mail.service';
import * as crypto from 'node:crypto';

@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly mail: MailService,
  ) {}

  /**
   * Generate a 6-digit OTP, store it, and email it to the user.
   * Returns the session ID (not the code — code goes via email only).
   */
  async sendOtp(userId: string): Promise<{ sessionId: string }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user?.email) {
      throw new UnauthorizedException('No email configured for this account');
    }

    // Generate 6-digit code
    const code = crypto.randomInt(100000, 999999).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min TTL

    // Store session
    const session = await this.prisma.mfaSession.create({
      data: {
        user_id: userId,
        code,
        expires_at: expiresAt,
      },
    });

    // Send email (non-blocking)
    this.mail.sendMfaCode(user.email, code, user.username).catch((err) => {
      this.logger.error(`[MFA] Failed to send email to ${user.email}: ${err.message}`);
    });

    this.logger.log(`[MFA] OTP sent to ${user.email} (session: ${session.id})`);
    return { sessionId: session.id };
  }

  /**
   * Verify a submitted OTP code against an active session.
   * Returns the userId if valid.
   */
  async verifyOtp(sessionId: string, code: string): Promise<string> {
    const session = await this.prisma.mfaSession.findUnique({
      where: { id: sessionId },
    });
    if (!session) {
      throw new UnauthorizedException('Invalid session');
    }
    if (session.used) {
      throw new UnauthorizedException('Code already used');
    }
    if (new Date() > session.expires_at) {
      throw new UnauthorizedException('Code expired');
    }
    if (session.code !== code) {
      throw new UnauthorizedException('Invalid code');
    }

    // Mark as used
    await this.prisma.mfaSession.update({
      where: { id: sessionId },
      data: { used: true },
    });

    return session.user_id;
  }

  /**
   * Enable MFA for a user (requires email to be set).
   */
  async enableMfa(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user?.email) {
      throw new UnauthorizedException('Set an email address first before enabling MFA');
    }
    await this.prisma.user.update({
      where: { id: userId },
      data: { mfa_enabled: true },
    });
    this.logger.log(`[MFA] Enabled for user ${user.username} (${user.email})`);
  }

  /**
   * Disable MFA for a user (admin only).
   */
  async disableMfa(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { mfa_enabled: false },
    });
    this.logger.log(`[MFA] Disabled for user ${userId}`);
  }
}
