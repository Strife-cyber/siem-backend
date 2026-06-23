import { Controller, Get, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
} from '@nestjs/swagger';
import { DashboardService } from './dashboard.service';
import { DashboardTimelineQuery } from './dto/dashboard-stats.dto';

@ApiTags('Dashboard')
@ApiBearerAuth('BearerAuth')
@Controller('dashboard')
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  @Get('stats')
  @ApiOperation({ summary: 'Get real-time CTU crisis stats (FR-05.1)' })
  @ApiOkResponse({ description: 'Crisis Room data' })
  async getCrisisStats() {
    return this.dashboardService.getStats();
  }

  @Get('timeline')
  @ApiOperation({ summary: 'Get timeline for graphs' })
  @ApiOkResponse({ description: 'Array of timeline points' })
  getTimeline(@Query() _query: DashboardTimelineQuery) {
    return [];
  }
}
