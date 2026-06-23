import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole } from '../../generated/prisma/enums';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(username: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      return null;
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password_hash as string,
    );
    if (!isPasswordValid) {
      return null;
    }

    return {
      id: user.id,
      username: user.username,
      role: user.role,
    };
  }

  async signIn(username: string, password: string) {
    const user = await this.validateUser(username, password);
    if (!user) {
      throw new UnauthorizedException('Invalid username or password');
    }

    // Update last login timestamp
    await this.prisma.user.update({
      where: { id: user.id },
      data: { last_login: new Date() },
    });

    const payload = { sub: user.id, username: user.username, role: user.role };
    const access_token = await this.jwtService.signAsync(payload);

    return {
      access_token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    };
  }

  async signUp(username: string, password: string, role?: UserRole) {
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
        role: role ?? UserRole.READER,
      },
      select: {
        id: true,
        username: true,
        role: true,
        created_at: true,
      },
    });

    return user;
  }

  async getProfile(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
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
