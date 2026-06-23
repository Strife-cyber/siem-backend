import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { createHash, timingSafeEqual } from 'node:crypto';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const apiKey = request.headers['x-api-key'] as string | undefined;

    if (!apiKey) {
      throw new UnauthorizedException(
        'Missing API key: provide X-API-Key header',
      );
    }

    const keyPrefix = apiKey.substring(0, 8);
    const keyHash = createHash('sha256').update(apiKey).digest('hex');

    const storedKey = await this.prisma.apiKey.findFirst({
      where: { key_prefix: keyPrefix, is_active: true },
      select: { id: true, key_hash: true },
    });

    if (!storedKey) {
      throw new UnauthorizedException('Invalid API key');
    }

    const storedHash = Buffer.from(storedKey.key_hash, 'hex');
    const providedHash = Buffer.from(keyHash, 'hex');

    if (storedHash.length !== providedHash.length) {
      throw new UnauthorizedException('Invalid API key');
    }

    const isValid = timingSafeEqual(storedHash, providedHash);
    if (!isValid) {
      throw new UnauthorizedException('Invalid API key');
    }

    // Update last_used_at without blocking the request
    await this.prisma.apiKey
      .update({
        where: { id: storedKey.id },
        data: { last_used_at: new Date() },
      })
      .catch(() => {
        // Non-critical — don't fail the request
      });

    return true;
  }
}
