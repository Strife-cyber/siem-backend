import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../../generated/prisma/enums';
import {
  CreateUserDto,
  UpdateUserDto,
  UpdateRetentionDto,
} from './dto/user.dto';

@ApiTags('Admin')
@ApiBearerAuth('BearerAuth')
@Roles(UserRole.ADMIN)
@Controller('admin')
export class AdminController {
  @Get('users')
  @ApiOperation({ summary: 'List all CTU users (ADMIN only)' })
  @ApiOkResponse({ description: 'User list' })
  async listUsers() {
    return [];
  }

  @Post('users')
  @ApiOperation({ summary: 'Create a new user (ADMIN only)' })
  @ApiCreatedResponse({ description: 'User created' })
  async createUser(@Body() _dto: CreateUserDto) {
    return {};
  }

  @Put('users/:userId')
  @ApiOperation({ summary: 'Update user role/status (ADMIN only)' })
  @ApiOkResponse({ description: 'User updated' })
  async updateUser(
    @Param('userId') _userId: string,
    @Body() _dto: UpdateUserDto,
  ) {
    return {};
  }

  @Delete('users/:userId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete/deactivate user (ADMIN only)' })
  @ApiOkResponse({ description: 'Deleted' })
  async deleteUser(@Param('userId') _userId: string) {
    return;
  }

  @Get('retention')
  @ApiOperation({ summary: 'Get current retention policies (FR-02.2)' })
  @ApiOkResponse({ description: 'Policies' })
  async getRetentionPolicies() {
    return [];
  }

  @Put('retention')
  @ApiOperation({ summary: 'Update retention policy (ADMIN only)' })
  @ApiOkResponse({ description: 'Updated' })
  async updateRetentionPolicy(@Body() _dto: UpdateRetentionDto) {
    return {};
  }
}
