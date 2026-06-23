import { Controller, Get, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
} from '@nestjs/swagger';
import { DashboardTimelineQuery } from './dto/dashboard-stats.dto';

@ApiTags('Dashboard')
@ApiBearerAuth('BearerAuth')
@Controller('dashboard')
export class DashboardController {
  @Get('stats')
  @ApiOperation({ summary: 'Get real-time CTU crisis stats (FR-05.1)' })
  @ApiOkResponse({ description: 'Crisis Room data' })
  async getCrisisStats() {
    return {
      critical_alerts: 0,
      high_alerts: 0,
      open_incidents: 0,
      logs_per_hour: 0,
      top_attackers: [],
      system_status: 'OK',
    };
  }

  @Get('timeline')
  @ApiOperation({ summary: 'Get timeline for graphs' })
  @ApiOkResponse({ description: 'Array of timeline points' })
  async getTimeline(@Query() _query: DashboardTimelineQuery) {
    return [];
  }
}
