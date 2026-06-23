import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { createHash } from 'node:crypto';
import { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';
import type { CreateLogDto } from '../dto/create-log.dto';

@Processor('logs')
export class LogsProcessor extends WorkerHost {
  constructor(private readonly elasticsearchService: ElasticsearchService) {
    super();
  }

  async process(job: Job<{ logs: CreateLogDto[] }>) {
    switch (job.name) {
      case 'normalize': {
        const normalized = this.normalizeLogs(job.data.logs as CreateLogDto[]);
        await this.elasticsearchService.bulkInsert(normalized);
        break;
      }
    }
  }

  private normalizeLogs(rawLogs: CreateLogDto[]): NormalizedLog[] {
    const now = new Date().toISOString();

    return rawLogs.map((log) => {
      const rawMessage = log.raw_message;
      const ingestionHash = createHash('sha256')
        .update(rawMessage)
        .digest('hex');

      const normalized: NormalizedLog = {
        collected_at: log.collected_at,
        normalized_at: now,
        source_type: log.source_type,
        hostname: log.hostname,
        source_ip: log.source_ip,
        destination_ip: log.destination_ip,
        source_port: log.source_port,
        destination_port: log.destination_port,
        user_principal: log.user_principal,
        user_security_id: log.user_security_id,
        event_taxonomy: log.event_taxonomy,
        action: log.action,
        outcome: log.outcome,
        severity: log.severity,
        raw_message: rawMessage,
        tags: log.tags,
        ingestion_hash: ingestionHash,
      };

      return normalized;
    });
  }
}
