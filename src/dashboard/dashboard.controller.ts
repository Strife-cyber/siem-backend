import { Controller, Get, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { DashboardService } from './dashboard.service';
import { DashboardOverviewQuery } from './dto/dashboard-stats.dto';

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

  @Get('overview')
  @ApiOperation({ summary: 'Get all dashboard graphs in one call' })
  @ApiQuery({
    name: 'interval',
    required: false,
    enum: ['16h', '24h', '7d', '30d'],
  })
  @ApiQuery({ name: 'source_type', required: false })
  @ApiOkResponse({ description: 'Complete dashboard overview payload' })
  async getOverview(@Query() query: DashboardOverviewQuery) {
    return this.dashboardService.getOverview(query.interval, query.source_type);
  }
}
