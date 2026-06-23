import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { ReportGenerationDto } from './dto/report.dto';

@ApiTags('Reports')
@ApiBearerAuth('BearerAuth')
@Controller('reports')
export class ReportsController {
  @Post('generate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Generate PDF/Excel report (FR-05.5)' })
  @ApiCreatedResponse({ description: 'Report generation queued' })
  generateReport(@Body() _dto: ReportGenerationDto) {
    return {
      job_id: '00000000-0000-0000-0000-000000000000',
      estimated_time_seconds: 30,
    };
  }

  @Get('download/:jobId')
  @ApiOperation({ summary: 'Download generated report' })
  @ApiOkResponse({ description: 'File download' })
  downloadReport(@Param('jobId') _jobId: string) {
    return {};
  }
}
