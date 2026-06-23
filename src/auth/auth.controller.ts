import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async signIn(@Body() dto: SignInDto) {
    return this.authService.signIn(dto.username, dto.password);
  }

  @Public()
  @HttpCode(HttpStatus.CREATED)
  @Post('register')
  async signUp(@Body() dto: SignUpDto) {
    return this.authService.signUp(dto.username, dto.password, dto.role);
  }

  @Get('profile')
  async getProfile(@CurrentUser('sub') userId: string) {
    return this.authService.getProfile(userId);
  }
}
