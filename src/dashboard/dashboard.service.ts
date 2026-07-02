import { Injectable, Logger } from '@nestjs/common';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { PrismaService } from '../prisma/prisma.service';

export interface OverviewResult {
  generated_at: string;
  interval: string;
  stats: {
    critical_alerts: number;
    high_alerts: number;
    open_incidents: number;
    logs_per_hour: number;
    system_status: string;
  };
  severity_distribution: Record<string, number>;
  events_timeline: Array<{
    bucket_start: string;
    bucket_end: string;
    label: string;
    count: number;
  }>;
  top_sources: Array<{
    source_ip: string;
    count: number;
    percentage: number;
  }>;
  threat_types: Array<{
    type: string;
    key: string;
    count: number;
    percentage: number;
  }>;
  login_failures: Array<{
    bucket_start: string;
    bucket_end: string;
    label: string;
    count: number;
    threat_level: string;
    description: string;
  }>;
  suspicious_activity_heatmap: Array<{
    day: string;
    hour_block: string;
    score: number;
    level: string;
    description: string;
  }>;
}

@Injectable()
export class DashboardService {
  private readonly logger = new Logger(DashboardService.name);

  /** Simple in-memory cache with TTL */
  private cache = new Map<string, { data: any; expiresAt: number }>();
  private readonly CACHE_TTL_MS = 15_000;

  constructor(
    private readonly prisma: PrismaService,
    private readonly elasticsearch: ElasticsearchService,
  ) {}

  private getCached<T>(key: string): T | null {
    const entry = this.cache.get(key);
    if (entry && entry.expiresAt > Date.now()) return entry.data as T;
    this.cache.delete(key);
    return null;
  }

  private setCache(key: string, data: any): void {
    this.cache.set(key, { data, expiresAt: Date.now() + this.CACHE_TTL_MS });
  }

  // ──────────────────────────────────────────────
  //  Stats (existing, kept for backward compat)
  // ──────────────────────────────────────────────

  async getStats() {
    const [openIncidents, criticalAlerts, highAlerts] = await Promise.all([
      this.prisma.incident.count({ where: { status: 'OPEN' } }),
      this.prisma.incident.count({
        where: {
          severity: 'CRITICAL',
          status: { in: ['OPEN', 'IN_PROGRESS'] },
        },
      }),
      this.prisma.incident.count({
        where: { severity: 'HIGH', status: { in: ['OPEN', 'IN_PROGRESS'] } },
      }),
    ]);

    return {
      critical_alerts: criticalAlerts,
      high_alerts: highAlerts,
      open_incidents: openIncidents,
      logs_per_hour: 0,
      top_attackers: [],
      system_status: 'OK',
    };
  }

  // ──────────────────────────────────────────────
  //  Overview (aggregates all 6 graphs)
  // ──────────────────────────────────────────────

  async getOverview(
    interval = '24h',
    sourceType?: string,
  ): Promise<OverviewResult> {
    const cacheKey = `overview:${interval}:${sourceType ?? '*'}`;
    const cached = this.getCached<OverviewResult>(cacheKey);
    if (cached) return cached;

    const generatedAt = new Date().toISOString();
    const intervalMs = this.parseInterval(interval);

    const [
      stats,
      severityDistribution,
      eventsTimeline,
      topSources,
      threatTypes,
      loginFailures,
      heatmap,
    ] = await Promise.all([
      this.getStats(),
      this.getSeverityDistribution(),
      this.getEventsTimeline(intervalMs, sourceType),
      this.getTopSources(intervalMs),
      this.getThreatTypes(intervalMs, sourceType),
      this.getLoginFailures(intervalMs),
      this.getSuspiciousActivityHeatmap(intervalMs),
    ]);

    const result: OverviewResult = {
      generated_at: generatedAt,
      interval,
      stats: { ...stats, logs_per_hour: stats.logs_per_hour || 0 },
      severity_distribution: severityDistribution,
      events_timeline: eventsTimeline,
      top_sources: topSources,
      threat_types: threatTypes,
      login_failures: loginFailures,
      suspicious_activity_heatmap: heatmap,
    };

    this.setCache(cacheKey, result);
    return result;
  }

  // ──────────────────────────────────────────────
  //  4.1 Severity Distribution
  // ──────────────────────────────────────────────

  private async getSeverityDistribution(): Promise<Record<string, number>> {
    const counts = await this.prisma.incident.groupBy({
      by: ['severity'],
      where: { status: { in: ['OPEN', 'IN_PROGRESS'] } },
      _count: { severity: true },
    });

    const distribution: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      WARNING: 0,
      INFO: 0,
    };
    for (const row of counts) {
      distribution[row.severity] = row._count.severity;
    }
    return distribution;
  }

  // ──────────────────────────────────────────────
  //  4.2 Events Timeline
  // ──────────────────────────────────────────────

  private async getEventsTimeline(
    intervalMs: number,
    sourceType?: string,
  ): Promise<
    Array<{
      bucket_start: string;
      bucket_end: string;
      label: string;
      count: number;
    }>
  > {
    const now = new Date();
    const since = new Date(now.getTime() - intervalMs);

    const filters: Record<string, any>[] = [
      {
        range: {
          collected_at: { gte: since.toISOString(), lte: now.toISOString() },
        },
      },
    ];
    if (sourceType) filters.push({ term: { source_type: sourceType } });

    const result = await this.elasticsearch
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: { bool: { filter: filters } },
        aggs: {
          timeline: {
            date_histogram: {
              field: 'collected_at',
              fixed_interval: intervalMs <= 86_400_000 ? '1h' : '24h',
              min_doc_count: 0,
              extended_bounds: {
                min: since.toISOString(),
                max: now.toISOString(),
              },
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.timeline?.buckets ?? [];
    return buckets.map((b: any) => {
      const start = new Date(b.key as string | number);
      const end = new Date(
        start.getTime() + (intervalMs <= 86_400_000 ? 3_600_000 : 86_400_000),
      );
      return {
        bucket_start: start.toISOString(),
        bucket_end: end.toISOString(),
        label:
          intervalMs <= 86_400_000
            ? start.toISOString().slice(11, 16)
            : start.toISOString().slice(0, 10),
        count: b.doc_count,
      };
    });
  }

  // ──────────────────────────────────────────────
  //  4.3 Top Source IPs
  // ──────────────────────────────────────────────

  private async getTopSources(
    intervalMs: number,
  ): Promise<Array<{ source_ip: string; count: number; percentage: number }>> {
    const now = new Date();
    const since = new Date(now.getTime() - intervalMs);

    const result = await this.elasticsearch
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              {
                range: {
                  collected_at: {
                    gte: since.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
            ],
            must_not: [{ term: { source_ip: '0.0.0.0' } }],
          },
        },
        aggs: {
          top_ips: {
            terms: { field: 'source_ip', size: 5, order: { _count: 'desc' } },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.top_ips?.buckets ?? [];
    const maxCount = buckets.length > 0 ? buckets[0].doc_count : 0;

    return buckets.map((b: any) => ({
      source_ip: b.key,
      count: b.doc_count,
      percentage:
        maxCount > 0 ? Number(((b.doc_count / maxCount) * 100).toFixed(2)) : 0,
    }));
  }

  // ──────────────────────────────────────────────
  //  4.4 Threat Types
  // ──────────────────────────────────────────────

  private async getThreatTypes(
    intervalMs: number,
    sourceType?: string,
  ): Promise<
    Array<{ type: string; key: string; count: number; percentage: number }>
  > {
    const now = new Date();
    const since = new Date(now.getTime() - intervalMs);

    const filters: Record<string, any>[] = [
      {
        range: {
          collected_at: { gte: since.toISOString(), lte: now.toISOString() },
        },
      },
    ];
    if (sourceType) filters.push({ term: { source_type: sourceType } });

    const result = await this.elasticsearch
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: { bool: { filter: filters } },
        aggs: {
          taxonomies: {
            terms: {
              field: 'event_taxonomy',
              size: 10,
              order: { _count: 'desc' },
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.taxonomies?.buckets ?? [];
    const total = buckets.reduce((s: number, b: any) => s + b.doc_count, 0);

    const normalizeLabel = (key: string): string => {
      return key
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase())
        .replace(/\./g, ' - ');
    };

    return buckets.map((b: any) => ({
      type: normalizeLabel(b.key as string),
      key: b.key,
      count: b.doc_count,
      percentage:
        total > 0 ? Number(((b.doc_count / total) * 100).toFixed(2)) : 0,
    }));
  }

  // ──────────────────────────────────────────────
  //  4.5 Login Failures
  // ──────────────────────────────────────────────

  private async getLoginFailures(intervalMs: number): Promise<
    Array<{
      bucket_start: string;
      bucket_end: string;
      label: string;
      count: number;
      threat_level: string;
      description: string;
    }>
  > {
    const now = new Date();
    const since = new Date(now.getTime() - intervalMs);

    const result = await this.elasticsearch
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              {
                range: {
                  collected_at: {
                    gte: since.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
              { term: { action: 'login' } },
              { term: { outcome: 'failure' } },
            ],
          },
        },
        aggs: {
          failures: {
            date_histogram: {
              field: 'collected_at',
              fixed_interval: '2h',
              min_doc_count: 0,
              extended_bounds: {
                min: since.toISOString(),
                max: now.toISOString(),
              },
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.failures?.buckets ?? [];

    return buckets.map((b: any) => {
      const start = new Date(b.key as string | number);
      const count: number = b.doc_count;
      let threatLevel: string;
      let description: string;

      if (count > 100) {
        threatLevel = 'HIGH';
        description = 'Attaque par force brute probable depuis IP externe';
      } else if (count >= 40) {
        threatLevel = 'MEDIUM';
        description = "Suspicion moderee d'activite anormale";
      } else {
        threatLevel = 'LOW';
        description = 'Activite normale';
      }

      const label = `${String(start.getUTCHours()).padStart(2, '0')}h-${String(start.getUTCHours() + 2).padStart(2, '0')}h`;
      return {
        bucket_start: start.toISOString(),
        bucket_end: new Date(start.getTime() + 7_200_000).toISOString(),
        label,
        count,
        threat_level: threatLevel,
        description,
      };
    });
  }

  // ──────────────────────────────────────────────
  //  4.6 Suspicious Activity Heatmap
  // ──────────────────────────────────────────────

  private async getSuspiciousActivityHeatmap(intervalMs: number): Promise<
    Array<{
      day: string;
      hour_block: string;
      score: number;
      level: string;
      description: string;
    }>
  > {
    const now = new Date();
    const since = new Date(now.getTime() - intervalMs);

    // Get high-severity events grouped by day-of-week + hour
    const result = await this.elasticsearch
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              {
                range: {
                  collected_at: {
                    gte: since.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
              { range: { severity: { gte: 5 } } },
            ],
          },
        },
        aggs: {
          by_day_of_week: {
            terms: { field: 'hostname', size: 1 }, // dummy — we'll process client-side
            aggs: {
              by_hour: {
                date_histogram: {
                  field: 'collected_at',
                  fixed_interval: '4h',
                  min_doc_count: 1,
                },
              },
            },
          },
        },
      })
      .then((r) => r as any);

    // Also get CRITICAL incidents per day
    const incidents = await this.prisma.incident.findMany({
      where: {
        triggered_at: { gte: since },
        severity: { in: ['CRITICAL', 'HIGH'] },
      },
      select: { triggered_at: true, severity: true, confidence_score: true },
    });

    const days = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
    const hourBlocks = [
      '00h-04h',
      '04h-08h',
      '08h-12h',
      '12h-16h',
      '16h-20h',
      '20h-00h',
    ];

    // Build a grid: day x hourblock -> score
    const grid = new Map<string, { score: number; reasons: string[] }>();

    // Score from ES high-severity events
    const buckets = result?.aggregations?.by_day_of_week?.buckets ?? [];
    for (const hostBucket of buckets) {
      const hourBuckets = hostBucket?.by_hour?.buckets ?? [];
      for (const b of hourBuckets) {
        const d = new Date(b.key as string | number);
        const dayIdx = d.getUTCDay();
        const hour = d.getUTCHours();
        const blockIdx = Math.floor(hour / 4);
        const key = `${dayIdx}:${blockIdx}`;
        const existing = grid.get(key) ?? { score: 0, reasons: [] };
        existing.score += Math.min(b.doc_count as number, 3);
        existing.reasons.push('evenements a haute severite');
        grid.set(key, existing);
      }
    }

    // Score from incidents
    for (const inc of incidents) {
      const d = new Date(inc.triggered_at);
      const dayIdx = d.getUTCDay();
      const hour = d.getUTCHours();
      const blockIdx = Math.floor(hour / 4);
      const key = `${dayIdx}:${blockIdx}`;
      const existing = grid.get(key) ?? { score: 0, reasons: [] };
      const incScore =
        inc.severity === 'CRITICAL' ? 3 : inc.confidence_score >= 70 ? 2 : 1;
      existing.score = Math.max(existing.score, incScore);
      existing.reasons.push(`incident ${inc.severity}`);
      grid.set(key, existing);
    }

    const heatmap: Array<{
      day: string;
      hour_block: string;
      score: number;
      level: string;
      description: string;
    }> = [];

    for (let d = 0; d < 7; d++) {
      for (let h = 0; h < 6; h++) {
        const key = `${d}:${h}`;
        const cell = grid.get(key);
        const score = cell?.score ?? 0;

        let level: string;
        let description: string;
        if (score >= 3) {
          level = 'CRITICAL';
          description =
            cell?.reasons.join(', ') ?? 'Activite critique detectee';
        } else if (score === 2) {
          level = 'MEDIUM';
          description =
            cell?.reasons.join(', ') ?? 'Signaux suspects multiples';
        } else if (score === 1) {
          level = 'MINOR';
          description =
            cell?.reasons.join(', ') ?? 'Evenements legerement anormaux';
        } else {
          level = 'NONE';
          description = 'Aucune activite suspecte';
        }

        heatmap.push({
          day: days[d],
          hour_block: hourBlocks[h],
          score,
          level,
          description,
        });
      }
    }

    return heatmap;
  }

  // ──────────────────────────────────────────────
  //  Helpers
  // ──────────────────────────────────────────────

  private parseInterval(interval: string): number {
    const match = interval.match(/^(\d+)([hd])$/);
    if (!match) return 86_400_000; // default 24h
    const value = parseInt(match[1], 10);
    return match[2] === 'd' ? value * 86_400_000 : value * 3_600_000;
  }
}
