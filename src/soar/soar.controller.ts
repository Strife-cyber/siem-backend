import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { PlaybookExecutionDto, AbortPlaybookDto } from './dto/soar.dto';

@ApiTags('SOAR')
@ApiBearerAuth('BearerAuth')
@Controller('soar')
export class SoarController {
  @Post('execute')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Execute a SOAR playbook (FR-04.2)' })
  @ApiCreatedResponse({ description: 'Playbook queued' })
  async executePlaybook(@Body() _dto: PlaybookExecutionDto) {
    return {
      execution_id: '00000000-0000-0000-0000-000000000000',
      status: 'PENDING',
    };
  }

  @Post('abort')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Abort a pending CONFIRM playbook (FR-04.2)' })
  @ApiOkResponse({ description: 'Aborted successfully' })
  async abortPlaybook(@Body() _dto: AbortPlaybookDto) {
    return { status: 'aborted' };
  }
}
