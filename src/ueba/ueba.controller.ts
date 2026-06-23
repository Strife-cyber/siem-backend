import { Controller, Get, Param, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';

@ApiTags('UEBA')
@ApiBearerAuth('BearerAuth')
@Controller('ueba')
export class UebaController {
  @Get('users')
  @ApiOperation({ summary: 'List all UEBA risk profiles (FR-04.8)' })
  @ApiQuery({ name: 'min_risk', required: false, type: Number })
  @ApiQuery({ name: 'max_risk', required: false, type: Number })
  @ApiOkResponse({ description: 'UEBA profiles' })
  async listUebaProfiles() {
    return [];
  }

  @Get('users/:userPrincipal')
  @ApiOperation({ summary: "Get specific user's risk profile" })
  @ApiOkResponse({ description: 'Profile data' })
  async getUebaProfile(@Param('userPrincipal') _userPrincipal: string) {
    return {};
  }
}
