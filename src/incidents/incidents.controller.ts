import { Controller, Get, Patch, Param, Body, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { IncidentsService } from './incidents.service';
import { IncidentUpdateDto } from './dto/incident-update.dto';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

@ApiTags('Incidents')
@ApiBearerAuth('BearerAuth')
@Controller('incidents')
export class IncidentsController {
  constructor(private readonly incidentsService: IncidentsService) {}

  @Get()
  @ApiOperation({ summary: 'List all incidents with filters' })
  @ApiQuery({
    name: 'status',
    required: false,
    enum: ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'],
  })
  @ApiQuery({
    name: 'severity',
    required: false,
    enum: ['INFO', 'WARNING', 'HIGH', 'CRITICAL'],
  })
  @ApiQuery({ name: 'from', required: false })
  @ApiQuery({ name: 'to', required: false })
  @ApiOkResponse({ description: 'List of incidents' })
  async listIncidents(
    @Query('status') status?: string,
    @Query('severity') severity?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    return this.incidentsService.findAll({ status, severity, from, to });
  }

  @Get(':incidentId')
  @ApiOperation({ summary: 'Get full incident details' })
  @ApiOkResponse({ description: 'Incident details' })
  async getIncident(
    @Param('incidentId') incidentId: string,
    @CurrentUser('sub') userId: string,
  ) {
    return this.incidentsService.findOne(incidentId, userId);
  }

  @Patch(':incidentId')
  @ApiOperation({ summary: 'Update incident status (ANALYST or ADMIN only)' })
  @ApiOkResponse({ description: 'Updated incident' })
  async updateIncident(
    @Param('incidentId') incidentId: string,
    @Body() dto: IncidentUpdateDto,
    @CurrentUser('sub') userId: string,
  ) {
    return this.incidentsService.update(incidentId, dto, userId);
  }
}
