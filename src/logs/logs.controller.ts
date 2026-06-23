import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiSecurity,
} from '@nestjs/swagger';
import { LogsService } from './logs.service';
import { CreateLogDto } from './dto/create-log.dto';
import { SearchLogsDto } from './dto/search-logs.dto';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { Public } from '../auth/decorators/public.decorator';

@ApiTags('Logs')
@Controller('logs')
export class LogsController {
  constructor(private readonly logsService: LogsService) {}

  @Public()
  @UseGuards(ApiKeyGuard)
  @Post()
  @ApiSecurity('X-API-Key')
  @ApiOperation({ summary: 'Ingest raw logs from collector agents (FR-01.1)' })
  @ApiCreatedResponse({ description: 'Logs accepted for processing' })
  async ingest(@Body() logs: CreateLogDto[]) {
    return this.logsService.ingest(logs);
  }

  @ApiBearerAuth('BearerAuth')
  @Get('search')
  @ApiOperation({ summary: 'Advanced log search with full-text (FR-05.2)' })
  @ApiOkResponse({ description: 'Paginated log results' })
  async search(@Query() query: SearchLogsDto) {
    return this.logsService.search(query);
  }
}
