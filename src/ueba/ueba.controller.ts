import { Controller, Get, Param, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { UebaService } from './ueba.service';

@ApiTags('UEBA')
@ApiBearerAuth('BearerAuth')
@Controller('ueba')
export class UebaController {
  constructor(private readonly uebaService: UebaService) {}

  @Get('users')
  @ApiOperation({ summary: 'List all UEBA risk profiles (FR-04.8)' })
  @ApiQuery({ name: 'min_risk', required: false, type: Number })
  @ApiQuery({ name: 'max_risk', required: false, type: Number })
  @ApiOkResponse({ description: 'UEBA profiles' })
  async listUebaProfiles(
    @Query('min_risk') minRisk?: number,
    @Query('max_risk') maxRisk?: number,
  ) {
    return this.uebaService.findAll(minRisk, maxRisk);
  }

  @Get('users/:userPrincipal')
  @ApiOperation({ summary: "Get specific user's risk profile" })
  @ApiOkResponse({ description: 'Profile data' })
  async getUebaProfile(@Param('userPrincipal') userPrincipal: string) {
    return this.uebaService.findOne(userPrincipal);
  }
}
