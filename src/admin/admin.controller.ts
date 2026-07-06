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
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { UserRole } from '../../generated/prisma/enums';
import { AdminService } from './admin.service';
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
  constructor(private readonly adminService: AdminService) {}

  @Get('users')
  @ApiOperation({ summary: 'List all CTU users (ADMIN only)' })
  @ApiOkResponse({ description: 'User list' })
  async listUsers() {
    return this.adminService.listUsers();
  }

  @Post('users')
  @ApiOperation({ summary: 'Create a new user (ADMIN only)' })
  @ApiCreatedResponse({ description: 'User created' })
  async createUser(
    @Body() dto: CreateUserDto,
    @CurrentUser('sub') actingUserId: string,
  ) {
    return this.adminService.createUser(dto, actingUserId);
  }

  @Put('users/:userId')
  @ApiOperation({ summary: 'Update user role/status (ADMIN only)' })
  @ApiOkResponse({ description: 'User updated' })
  async updateUser(
    @Param('userId') userId: string,
    @Body() dto: UpdateUserDto,
    @CurrentUser('sub') actingUserId: string,
  ) {
    return this.adminService.updateUser(userId, dto, actingUserId);
  }

  @Delete('users/:userId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete/deactivate user (ADMIN only)' })
  @ApiOkResponse({ description: 'Deleted' })
  async deleteUser(
    @Param('userId') userId: string,
    @CurrentUser('sub') actingUserId: string,
  ) {
    await this.adminService.deleteUser(userId, actingUserId);
  }

  @Get('retention')
  @ApiOperation({ summary: 'Get current retention policies (FR-02.2)' })
  @ApiOkResponse({ description: 'Policies' })
  async getRetentionPolicies() {
    return this.adminService.getRetentionPolicies();
  }

  @Put('retention')
  @ApiOperation({ summary: 'Update retention policy (ADMIN only)' })
  @ApiOkResponse({ description: 'Updated' })
  async updateRetentionPolicy(@Body() dto: UpdateRetentionDto) {
    return this.adminService.updateRetentionPolicy(dto);
  }
}
