import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { MfaService } from './mfa.service';
import { MailModule } from '../mail/mail.module';
import { AuditModule } from '../audit/audit.module';
import { getJwtSecret } from './jwt-secret';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: getJwtSecret(),
      signOptions: { expiresIn: '24h' },
    }),
    MailModule,
    AuditModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, MfaService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
