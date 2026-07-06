import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole } from '../../generated/prisma/enums';
import { AuditService } from '../audit/audit.service';
import { MfaService } from './mfa.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly audit: AuditService,
    private readonly mfa: MfaService,
  ) {}

  async validateUser(username: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: { username },
    });
    if (!user) return null;

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) return null;

    return {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
      mfa_enabled: user.mfa_enabled,
    };
  }

  async signIn(
    username: string,
    password: string,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const user = await this.validateUser(username, password);
    if (!user) {
      // Audit: log failed login attempt (no user id available — log with empty)
      await this.audit.log({
        userId: 'unknown',
        action: 'LOGIN_FAILED',
        metadata: { username, reason: 'invalid_credentials' },
        ipAddress,
        userAgent,
      });
      throw new UnauthorizedException('Invalid username or password');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { last_login: new Date() },
    });

    // Audit: log successful login
    await this.audit.log({
      userId: user.id,
      action: 'LOGIN',
      metadata: { username },
      ipAddress,
      userAgent,
    });

    // If MFA is enabled, send OTP and require verification
    if (user.mfa_enabled) {
      const { sessionId } = await this.mfa.sendOtp(user.id);
      return {
        mfa_required: true,
        session_id: sessionId,
        user: { id: user.id, username: user.username, role: user.role },
      };
    }

    // No MFA — issue JWT directly
    const payload = { sub: user.id, username: user.username, role: user.role };
    const access_token = await this.jwtService.signAsync(payload);

    return {
      access_token,
      user: { id: user.id, username: user.username, role: user.role },
    };
  }

  async signUp(
    username: string,
    password: string,
    role?: UserRole,
    email?: string,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const existingUser = await this.prisma.user.findUnique({
      where: { username },
    });
    if (existingUser) {
      throw new ConflictException('Username already exists');
    }

    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(password, salt);

    const user = await this.prisma.user.create({
      data: {
        username,
        password_hash,
        email,
        role: role ?? UserRole.READER,
      },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        created_at: true,
      },
    });

    // Audit: log user registration
    await this.audit.log({
      userId: user.id,
      action: 'USER_REGISTERED',
      metadata: { username, role: user.role },
      ipAddress,
      userAgent,
    });

    return user;
  }

  async verifyMfa(sessionId: string, code: string) {
    const userId = await this.mfa.verifyOtp(sessionId, code);

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true, role: true },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const payload = { sub: user.id, username: user.username, role: user.role };
    const access_token = await this.jwtService.signAsync(payload);

    return {
      access_token,
      user: { id: user.id, username: user.username, role: user.role },
    };
  }

  async enableMfa(userId: string, email: string) {
    // Set email first, then enable
    await this.prisma.user.update({
      where: { id: userId },
      data: { email },
    });
    await this.mfa.enableMfa(userId);
    return { mfa_enabled: true, email };
  }

  async disableMfa(userId: string) {
    await this.mfa.disableMfa(userId);
    return { mfa_enabled: false };
  }

  async getProfile(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        email: true,
        mfa_enabled: true,
        role: true,
        created_at: true,
        last_login: true,
        is_active: true,
      },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return user;
  }
}
