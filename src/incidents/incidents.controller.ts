import { Controller, Get, Patch, Param, Body } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { IncidentUpdateDto } from './dto/incident-update.dto';

@ApiTags('Incidents')
@ApiBearerAuth('BearerAuth')
@Controller('incidents')
export class IncidentsController {
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
  async listIncidents() {
    return [];
  }

  @Get(':incidentId')
  @ApiOperation({ summary: 'Get full incident details' })
  @ApiOkResponse({ description: 'Incident details' })
  async getIncident(@Param('incidentId') _incidentId: string) {
    return {};
  }

  @Patch(':incidentId')
  @ApiOperation({ summary: 'Update incident status (ANALYST or ADMIN only)' })
  @ApiOkResponse({ description: 'Updated incident' })
  async updateIncident(
    @Param('incidentId') _incidentId: string,
    @Body() _dto: IncidentUpdateDto,
  ) {
    return {};
  }
}
