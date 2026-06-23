import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { SoarService } from './soar.service';
import { PlaybookExecutionDto, AbortPlaybookDto } from './dto/soar.dto';

@ApiTags('SOAR')
@ApiBearerAuth('BearerAuth')
@Controller('soar')
export class SoarController {
  constructor(private readonly soarService: SoarService) {}

  @Post('execute')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Execute a SOAR playbook (FR-04.2)' })
  @ApiCreatedResponse({ description: 'Playbook queued' })
  async executePlaybook(@Body() dto: PlaybookExecutionDto) {
    return this.soarService.executePlaybook(dto);
  }

  @Post('abort')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Abort a pending CONFIRM playbook (FR-04.2)' })
  @ApiOkResponse({ description: 'Aborted successfully' })
  async abortPlaybook(@Body() dto: AbortPlaybookDto) {
    return this.soarService.abortPlaybook(dto.execution_id);
  }
}
