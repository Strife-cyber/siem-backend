import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
  Req,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { VerifyMfaDto, EnableMfaDto } from './dto/mfa.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  @ApiOperation({ summary: 'Authenticate user and get JWT' })
  @ApiOkResponse({ description: 'Returns JWT or mfa_required' })
  async signIn(@Body() dto: SignInDto, @Req() req: Request) {
    return this.authService.signIn(
      dto.username,
      dto.password,
      req.ip,
      req.headers['user-agent'],
    );
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('mfa/verify')
  @ApiOperation({ summary: 'Verify MFA code and complete login' })
  @ApiOkResponse({ description: 'Returns JWT after MFA verification' })
  async verifyMfa(@Body() dto: VerifyMfaDto) {
    return this.authService.verifyMfa(dto.session_id, dto.code);
  }

  @Public()
  @HttpCode(HttpStatus.CREATED)
  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiCreatedResponse({ description: 'User registered successfully' })
  async signUp(@Body() dto: SignUpDto, @Req() req: Request) {
    return this.authService.signUp(
      dto.username,
      dto.password,
      dto.role,
      dto.email,
      req.ip,
      req.headers['user-agent'],
    );
  }

  @ApiBearerAuth('BearerAuth')
  @Post('mfa/enable')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Enable MFA with email for OTP delivery' })
  @ApiOkResponse({ description: 'MFA enabled' })
  async enableMfa(
    @CurrentUser('sub') userId: string,
    @Body() dto: EnableMfaDto,
  ) {
    return this.authService.enableMfa(userId, dto.email);
  }

  @ApiBearerAuth('BearerAuth')
  @Post('mfa/disable')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Disable MFA for current user' })
  @ApiOkResponse({ description: 'MFA disabled' })
  async disableMfa(@CurrentUser('sub') userId: string) {
    return this.authService.disableMfa(userId);
  }

  @ApiBearerAuth('BearerAuth')
  @Get('profile')
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiOkResponse({ description: 'Current user data' })
  async getProfile(@CurrentUser('sub') userId: string) {
    return this.authService.getProfile(userId);
  }
}
