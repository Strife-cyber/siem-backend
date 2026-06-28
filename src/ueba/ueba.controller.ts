import {
  Controller,
  Get,
  Param,
  Query,
  Post,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
  ApiCreatedResponse,
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
  @ApiOkResponse({ description: 'UEBA profiles sorted by risk (desc)' })
  async listUebaProfiles(
    @Query('min_risk') minRisk?: number,
    @Query('max_risk') maxRisk?: number,
  ) {
    return this.uebaService.findAll(
      minRisk ? Number(minRisk) : undefined,
      maxRisk ? Number(maxRisk) : undefined,
    );
  }

  @Get('users/:userPrincipal')
  @ApiOperation({ summary: "Get specific user's UEBA risk profile" })
  @ApiOkResponse({ description: 'Profile data with baseline and risk score' })
  async getUebaProfile(@Param('userPrincipal') userPrincipal: string) {
    return this.uebaService.findOne(userPrincipal);
  }

  @Get('stats')
  @ApiOperation({ summary: 'UEBA system-wide statistics for Crisis Room' })
  @ApiOkResponse({ description: 'Aggregated UEBA metrics' })
  async getUebaStats() {
    return this.uebaService.getStats();
  }

  @Post('baselines/rebuild')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Trigger manual baseline rebuild for all users' })
  @ApiCreatedResponse({ description: 'Rebuild initiated' })
  async triggerBaselineRebuild() {
    return this.uebaService.triggerBaselineRebuild();
  }
}
