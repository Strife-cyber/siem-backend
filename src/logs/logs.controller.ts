import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { LogsService } from './logs.service';
import { CreateLogDto } from './dto/create-log.dto';
import { SearchLogsDto } from './dto/search-logs.dto';

@Controller('logs')
export class LogsController {
  constructor(private readonly logsService: LogsService) {}

  @Post()
  async ingest(@Body() logs: CreateLogDto[]) {
    return this.logsService.ingest(logs);
  }

  @Get('search')
  async search(@Query() query: SearchLogsDto) {
    return this.logsService.search(query);
  }
}
