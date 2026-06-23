import { Injectable } from '@nestjs/common';
import { Queue } from 'bullmq';
import { InjectQueue } from '@nestjs/bullmq';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import type { CreateLogDto } from './dto/create-log.dto';
import type { SearchLogsDto } from './dto/search-logs.dto';
import type { LogSearchQuery } from './interfaces/normalized-log.interface';

@Injectable()
export class LogsService {
  constructor(
    @InjectQueue('logs')
    private readonly logsQueue: Queue,
    private readonly elasticsearchService: ElasticsearchService,
  ) {}

  async ingest(logs: CreateLogDto[]) {
    await this.logsQueue.add('normalize', { logs });

    return {
      accepted: logs.length,
    };
  }

  async search(query: SearchLogsDto) {
    const esQuery: LogSearchQuery = {
      source_ip: query.source_ip,
      destination_ip: query.destination_ip,
      user_principal: query.user_principal,
      hostname: query.hostname,
      source_type: query.source_type,
      event_taxonomy: query.event_taxonomy,
      action: query.action,
      severity_min: query.severity_min,
      severity_max: query.severity_max,
      raw_message: query.raw_message,
      tags: query.tags,
      date_from: query.date_from,
      date_to: query.date_to,
      from: query.from,
      size: query.size,
      sort_field: query.sort_field,
      sort_order: query.sort_order,
    };

    return this.elasticsearchService.search(esQuery);
  }
}
