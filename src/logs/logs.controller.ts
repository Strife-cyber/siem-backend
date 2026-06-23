import { LogsService } from './logs.service';
import { CreateLogDto } from './dto/create-log.dto';
import { Body, Controller, Post } from '@nestjs/common';

@Controller('logs')
export class LogsController {
  constructor(private readonly logsService: LogsService) {}

  @Post()
  async ingest(@Body() logs: CreateLogDto[]) {
    return this.logsService.ingest(logs);
  }
}
