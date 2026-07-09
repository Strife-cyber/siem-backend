import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job, Queue } from 'bullmq';
import { InjectQueue } from '@nestjs/bullmq';
import { createHash } from 'node:crypto';
import { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';
import type { CreateLogDto } from '../dto/create-log.dto';
import { enrichLog } from '../enrichers/enricher.registry';
import { LogsRetentionService } from '../logs-retention.service';

@Processor('logs', { concurrency: 10 })
export class LogsProcessor extends WorkerHost {
  constructor(
    private readonly elasticsearchService: ElasticsearchService,
    @InjectQueue('ueba') private readonly uebaQueue: Queue,
    private readonly retentionService: LogsRetentionService,
  ) {
    super();
  }

  async process(job: Job<{ logs: CreateLogDto[] }>) {
    switch (job.name) {
      case 'normalize': {
        const rawLogs = job.data.logs;
        if (!Array.isArray(rawLogs) || rawLogs.length === 0) {
          return;
        }
        const normalized = this.normalizeLogs(rawLogs);
        const enriched = normalized.map((log) => ({
          ...log,
          ...enrichLog(log),
        }));
        await this.elasticsearchService.bulkInsert(enriched);

        // Push each normalized log to UEBA for behavioral scoring
        for (const log of normalized) {
          if (log.user_principal) {
            await this.uebaQueue
              .add('score', { log }, { attempts: 3 })
              .catch(() => {
                // Non-critical: UEBA scoring is best-effort
              });
          }
        }
        break;
      }
      case 'retention-archive': {
        await this.retentionService.archiveAndPurge(30);
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
        source_type: log.source_type?.toLowerCase() ?? '',
        hostname: log.hostname?.toLowerCase() ?? '',
        source_ip: log.source_ip,
        destination_ip: log.destination_ip,
        source_port: log.source_port,
        destination_port: log.destination_port,
        user_principal: log.user_principal?.toLowerCase(),
        user_security_id: log.user_security_id,
        event_taxonomy: log.event_taxonomy?.toLowerCase() ?? '',
        action: log.action?.toLowerCase() ?? '',
        outcome: log.outcome?.toLowerCase(),
        severity: log.severity,
        raw_message: rawMessage,
        tags: log.tags?.map((t) => t.toLowerCase()),
        ingestion_hash: ingestionHash,
      };

      return normalized;
    });
  }
}
