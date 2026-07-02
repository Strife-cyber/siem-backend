import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Res,
  HttpCode,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import type { Response } from 'express';
import * as fs from 'node:fs';
import { ReportsService } from './reports.service';
import { ReportGenerationDto } from './dto/report.dto';

@ApiTags('Reports')
@ApiBearerAuth('BearerAuth')
@Controller('reports')
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Post('generate')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Generate PDF/Excel/CSV report' })
  @ApiCreatedResponse({ description: 'Report generation queued' })
  async generate(@Body() dto: ReportGenerationDto) {
    return this.reportsService.generate({
      type: dto.format,
      start_date: dto.start_date,
      end_date: dto.end_date,
    });
  }

  @Get('status/:jobId')
  @ApiOperation({ summary: 'Check report generation status' })
  @ApiOkResponse({ description: 'Job status' })
  async status(@Param('jobId') jobId: string) {
    const job = this.reportsService.getJobStatus(jobId);
    if (!job) throw new NotFoundException('Job not found');
    return job;
  }

  @Get('download/:jobId')
  @ApiOperation({ summary: 'Download generated report file' })
  @ApiOkResponse({ description: 'File download' })
  async download(@Param('jobId') jobId: string, @Res() res: Response) {
    const result = this.reportsService.download(jobId);
    if (!result) throw new NotFoundException('Report not found or not ready');

    const ext = result.filename.endsWith('.pdf')
      ? 'application/pdf'
      : result.filename.endsWith('.xlsx')
        ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        : result.filename.endsWith('.csv')
          ? 'text/csv'
          : 'application/octet-stream';

    const stream = fs.createReadStream(result.filePath);
    res.setHeader('Content-Type', ext);
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${result.filename}"`,
    );
    stream.pipe(res);
  }

  @Get('list')
  @ApiOperation({ summary: 'List all available reports' })
  @ApiOkResponse({ description: 'Grouped file listing' })
  async list() {
    return this.reportsService.listReports();
  }
}
