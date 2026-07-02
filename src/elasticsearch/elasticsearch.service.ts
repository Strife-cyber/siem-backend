import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Client } from '@elastic/elasticsearch';
import type {
  NormalizedLog,
  LogSearchQuery,
} from '../logs/interfaces/normalized-log.interface';

const LOGS_INDEX_TEMPLATE = 'ctu-logs-template';
const LOGS_ILM_POLICY = 'ctu-30-days-ilm-policy';
const LOGS_ALIAS = 'ctu-logs';
const INITIAL_INDEX = 'ctu-logs-000001';

@Injectable()
export class ElasticsearchService implements OnModuleInit {
  private readonly logger = new Logger(ElasticsearchService.name);
  private readonly client: Client;

  constructor() {
    this.client = new Client({
      node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
    });
  }

  async onModuleInit() {
    await this.ensureIlmPolicy();
    await this.ensureIndexTemplate();
    await this.ensureInitialIndex();
    this.logger.log(
      'Elasticsearch initialized: ILM policy, index template, and initial index ready',
    );
  }

  private async ensureIlmPolicy() {
    try {
      await this.client.ilm.putLifecycle({
        name: LOGS_ILM_POLICY,
        policy: {
          phases: {
            hot: {
              min_age: '0ms',
              actions: {
                rollover: {
                  max_primary_shard_size: '50gb',
                  max_age: '7d',
                },
              },
            },
            delete: {
              min_age: '30d',
              actions: {
                delete: {
                  delete_searchable_snapshot: true,
                },
              },
            },
          },
        },
      });
      this.logger.log(`ILM policy "${LOGS_ILM_POLICY}" ensured`);
    } catch (error) {
      this.logger.error('Failed to create ILM policy', error);
    }
  }

  private async ensureIndexTemplate() {
    try {
      await this.client.indices.putIndexTemplate({
        name: LOGS_INDEX_TEMPLATE,
        index_patterns: [`${LOGS_ALIAS}-*`],
        priority: 100,
        template: {
          settings: {
            number_of_shards: 2,
            number_of_replicas: 0,
            'index.lifecycle.name': LOGS_ILM_POLICY,
            'index.lifecycle.rollover_alias': LOGS_ALIAS,
            analysis: {
              analyzer: {
                log_message_analyzer: {
                  type: 'standard',
                  stopwords: '_english_',
                },
              },
            },
          },
          mappings: {
            properties: {
              collected_at: { type: 'date' },
              normalized_at: { type: 'date' },
              source_type: { type: 'keyword' },
              hostname: { type: 'keyword' },
              source_ip: { type: 'ip' },
              destination_ip: { type: 'ip' },
              source_port: { type: 'integer' },
              destination_port: { type: 'integer' },
              user_principal: { type: 'keyword' },
              user_security_id: { type: 'keyword' },
              event_taxonomy: { type: 'keyword' },
              action: { type: 'keyword' },
              outcome: { type: 'keyword' },
              severity: { type: 'byte' },
              raw_message: {
                type: 'text',
                analyzer: 'log_message_analyzer',
                fields: {
                  keyword: { type: 'keyword', ignore_above: 256 },
                },
              },
              tags: { type: 'keyword' },
              ingestion_hash: { type: 'keyword' },
              confidence_score: { type: 'byte' },
              // ---- Enrichment fields (parsed from raw_message) ----
              event_id: { type: 'integer' },
              logon_type: { type: 'byte' },
              target_user: { type: 'keyword' },
              failure_reason: { type: 'keyword' },
              source_network_address: { type: 'ip' },
              workstation: { type: 'keyword' },
              auth_package: { type: 'keyword' },
              service_name: { type: 'keyword' },
              bytes_sent: { type: 'long' },
              bytes_recv: { type: 'long' },
              direction: { type: 'keyword' },
              protocol: { type: 'keyword' },
              duration_seconds: { type: 'integer' },
            },
            _meta: {
              version: '1.0',
              description: 'CTU Smart SIEM Golden Schema - FR-01.3',
            },
          },
        },
      });
      this.logger.log(`Index template "${LOGS_INDEX_TEMPLATE}" ensured`);
    } catch (error) {
      this.logger.error('Failed to create index template', error);
    }
  }

  private async ensureInitialIndex() {
    try {
      const exists = await this.client.indices.exists({ index: INITIAL_INDEX });
      if (!exists) {
        await this.client.indices.create({
          index: INITIAL_INDEX,
          aliases: {
            [LOGS_ALIAS]: { is_write_index: true },
          },
        });
        this.logger.log(
          `Initial index "${INITIAL_INDEX}" created with alias "${LOGS_ALIAS}"`,
        );
      }

      // Apply enrichment fields mapping to the existing index
      // (template only affects NEW indices, not existing ones)
      await this.client.indices.putMapping({
        index: INITIAL_INDEX,
        properties: {
          event_id: { type: 'integer' },
          logon_type: { type: 'byte' },
          target_user: { type: 'keyword' },
          failure_reason: { type: 'keyword' },
          source_network_address: { type: 'ip' },
          workstation: { type: 'keyword' },
          auth_package: { type: 'keyword' },
          service_name: { type: 'keyword' },
          bytes_sent: { type: 'long' },
          bytes_recv: { type: 'long' },
          direction: { type: 'keyword' },
          protocol: { type: 'keyword' },
          duration_seconds: { type: 'integer' },
        },
      });
      this.logger.log(
        `Enrichment fields mapping applied to "${INITIAL_INDEX}"`,
      );
    } catch (error: any) {
      // putMapping returns 400 if fields already exist — not a problem
      if (error?.meta?.statusCode === 400) {
        this.logger.log('Enrichment fields already mapped (no change needed)');
      } else {
        this.logger.error('Failed to update index mapping', error);
      }
    }
  }

  async bulkInsert(logs: NormalizedLog[]): Promise<{ indexed: number }> {
    if (logs.length === 0) {
      return { indexed: 0 };
    }

    const body = logs.flatMap((log) => [
      { index: { _index: LOGS_ALIAS } },
      log,
    ]);

    const response = await this.client.bulk({ body, refresh: 'wait_for' });

    if (response.errors) {
      const errorItems = response.items.filter((item) => item.index?.error);
      for (const item of errorItems.slice(0, 5)) {
        this.logger.warn(
          `ES bulk error: ${item.index?.error?.reason ?? 'unknown'} (type: ${item.index?.error?.type ?? 'unknown'})`,
        );
      }
      this.logger.warn(
        `Bulk insert completed with ${errorItems.length} error(s) out of ${logs.length} documents`,
      );
    }

    return { indexed: logs.length };
  }

  async search(query: LogSearchQuery) {
    const must: Record<string, unknown>[] = [];
    const filter: Record<string, unknown>[] = [];

    if (query.source_ip) {
      must.push({ term: { source_ip: query.source_ip } });
    }
    if (query.destination_ip) {
      must.push({ term: { destination_ip: query.destination_ip } });
    }
    if (query.user_principal) {
      must.push({ term: { user_principal: query.user_principal } });
    }
    if (query.hostname) {
      must.push({ term: { hostname: query.hostname } });
    }
    if (query.source_type) {
      must.push({ term: { source_type: query.source_type } });
    }
    if (query.event_taxonomy) {
      must.push({ term: { event_taxonomy: query.event_taxonomy } });
    }
    if (query.action) {
      must.push({ term: { action: query.action } });
    }
    if (query.tags && query.tags.length > 0) {
      must.push({ terms: { tags: query.tags } });
    }

    if (query.raw_message) {
      must.push({ match: { raw_message: query.raw_message } });
    }

    if (query.severity_min !== undefined || query.severity_max !== undefined) {
      const range: Record<string, number> = {};
      if (query.severity_min !== undefined) range.gte = query.severity_min;
      if (query.severity_max !== undefined) range.lte = query.severity_max;
      filter.push({ range: { severity: range } });
    }

    if (query.date_from || query.date_to) {
      const range: Record<string, string> = {};
      if (query.date_from) range.gte = query.date_from;
      if (query.date_to) range.lte = query.date_to;
      filter.push({ range: { collected_at: range } });
    }

    const response = await this.client.search({
      index: LOGS_ALIAS,
      track_total_hits: true,
      from: query.from ?? 0,
      size: query.size ?? 50,
      sort: [
        {
          [query.sort_field ?? 'collected_at']: {
            order: query.sort_order ?? 'desc',
          },
        },
      ],
      query: {
        bool: {
          must: must.length > 0 ? must : [{ match_all: {} }],
          filter,
        },
      },
    });

    return {
      total:
        typeof response.hits.total === 'number'
          ? response.hits.total
          : (response.hits.total?.value ?? 0),
      hits: response.hits.hits.map((hit) => ({
        id: hit._id,
        score: hit._score,
        source: hit._source as NormalizedLog,
      })),
    };
  }

  getClient(): Client {
    return this.client;
  }
}
