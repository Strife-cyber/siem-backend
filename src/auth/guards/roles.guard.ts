import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { UserRole } from '../../../generated/prisma/enums';
import { ROLES_KEY } from '../decorators/roles.decorator';
import type { JwtPayload } from '../decorators/current-user.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user as JwtPayload | undefined;

    if (!user) {
      throw new ForbiddenException('Access denied: no authenticated user');
    }

    const hasRole = requiredRoles.includes(user.role as UserRole);

    if (!hasRole) {
      throw new ForbiddenException(
        `Access denied: requires one of roles [${requiredRoles.join(', ')}]`,
      );
    }

    return true;
  }
}
