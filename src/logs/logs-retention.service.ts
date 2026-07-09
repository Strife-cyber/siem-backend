import { Injectable, Logger } from '@nestjs/common';
import { mkdir, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';

interface RetentionArchiveResult {
  archive_file?: string;
  archived_count: number;
  deleted_count: number;
  cutoff_iso: string;
}

@Injectable()
export class LogsRetentionService {
  private readonly logger = new Logger(LogsRetentionService.name);
  private readonly indexAlias = 'ctu-logs';

  constructor(private readonly elasticsearchService: ElasticsearchService) {}

  /**
   * Archive logs older than `retentionDays` into one JSON file,
   * then delete those archived documents from Elasticsearch.
   */
  async archiveAndPurge(retentionDays: number = 30): Promise<RetentionArchiveResult> {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    const cutoffIso = cutoff.toISOString();

    const archived = await this.archiveLogsOlderThan(cutoffIso);
    if (archived.archived_count === 0) {
      this.logger.log(
        `[Retention] No logs older than ${retentionDays} days. Nothing to purge.`,
      );
      return {
        archived_count: 0,
        deleted_count: 0,
        cutoff_iso: cutoffIso,
      };
    }

    const deleted = await this.deleteLogsOlderThan(cutoffIso);

    this.logger.log(
      `[Retention] Completed: archived=${archived.archived_count}, deleted=${deleted}, cutoff=${cutoffIso}`,
    );

    return {
      archive_file: archived.archive_file,
      archived_count: archived.archived_count,
      deleted_count: deleted,
      cutoff_iso: cutoffIso,
    };
  }

  private async archiveLogsOlderThan(
    cutoffIso: string,
  ): Promise<{ archive_file?: string; archived_count: number }> {
    const client = this.elasticsearchService.getClient();
    const backupDir = path.resolve(process.cwd(), 'backups', 'logs');
    await mkdir(backupDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const archivePath = path.join(backupDir, `logs-archive-before-${timestamp}.json`);

    const archivedDocs: Record<string, unknown>[] = [];
    let searchAfter: (string | number)[] | undefined;

    while (true) {
      const response = await client.search({
        index: this.indexAlias,
        size: 1000,
        sort: [{ collected_at: 'asc' }, { ingestion_hash: 'asc' }],
        search_after: searchAfter,
        query: {
          range: {
            collected_at: {
              lt: cutoffIso,
            },
          },
        },
      });

      const hits = response.hits.hits ?? [];
      if (hits.length === 0) break;

      for (const hit of hits) {
        archivedDocs.push(hit._source as Record<string, unknown>);
      }

      searchAfter = hits[hits.length - 1].sort as (string | number)[] | undefined;
      if (!searchAfter) break;
    }

    if (archivedDocs.length === 0) {
      return { archived_count: 0 };
    }

    await writeFile(archivePath, JSON.stringify(archivedDocs, null, 2), 'utf8');

    this.logger.log(
      `[Retention] Archived ${archivedDocs.length} logs to ${archivePath}`,
    );

    return {
      archive_file: archivePath,
      archived_count: archivedDocs.length,
    };
  }

  private async deleteLogsOlderThan(cutoffIso: string): Promise<number> {
    const client = this.elasticsearchService.getClient();
    const result = await client.deleteByQuery({
      index: this.indexAlias,
      refresh: true,
      conflicts: 'proceed',
      query: {
        range: {
          collected_at: {
            lt: cutoffIso,
          },
        },
      },
    });

    return result.deleted ?? 0;
  }
}
