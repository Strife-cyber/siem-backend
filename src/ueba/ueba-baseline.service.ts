import { Injectable, Logger } from '@nestjs/common';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { PrismaService } from '../prisma/prisma.service';
import type { UebaBaseline } from './interfaces/baseline.interface';

/**
 * Fields available in ES (from the golden schema mapping):
 *   collected_at (date), hostname (keyword), source_ip (ip),
 *   user_principal (keyword), action (keyword), outcome (keyword),
 *   raw_message (text), source_type (keyword)
 *
 * Fields NOT reliably available:
 *   - No dedicated "day_of_week" or "is_weekend" field
 *   - No dedicated "file_count" field (only in raw_message text)
 *   - bytes_sent / bytes_recv only from firewall enricher
 *
 * The baseline builder works with ONLY the available fields above.
 */
@Injectable()
export class UebaBaselineService {
  private readonly logger = new Logger(UebaBaselineService.name);

  constructor(
    private readonly es: ElasticsearchService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Build or refresh behavioral baselines for ALL users from ES data.
   * Queries the last 30 days of logs and computes per-user statistics.
   * Called nightly via BullMQ cron, or on-demand via API.
   */
  async buildAllBaselines(): Promise<{ usersProcessed: number }> {
    this.logger.log('Building behavioral baselines for all users...');

    const client = this.es.getClient();
    const thirtyDaysAgo = new Date(
      Date.now() - 30 * 24 * 60 * 60 * 1000,
    ).toISOString();

    // Step 1: Discover all unique users from ES
    // ES field: user_principal (keyword)
    const userResult = await client.search({
      index: 'ctu-logs',
      size: 0,
      query: {
        range: { collected_at: { gte: thirtyDaysAgo } },
      },
      aggs: {
        users: {
          terms: { field: 'user_principal', size: 500, min_doc_count: 1 },
        },
      },
    });

    const buckets = (userResult as any)?.aggregations?.users?.buckets ?? [];
    const userPrincipals: string[] = buckets.map((b: any) => b.key as string);

    this.logger.log(`Found ${userPrincipals.length} users with activity`);

    let processed = 0;
    for (const user of userPrincipals) {
      try {
        await this.buildBaselineForUser(user, thirtyDaysAgo);
        processed++;
      } catch (err: any) {
        this.logger.error(
          `Failed to build baseline for ${user}: ${err.message}`,
        );
      }
    }

    if (userPrincipals.length === 0) {
      this.logger.warn(
        'No users found in ES. Seed data first: npx tsx scripts/generate-synthetic-logs.ts',
      );
    }

    this.logger.log(
      `Baseline build complete: ${processed}/${userPrincipals.length} users`,
    );
    return { usersProcessed: processed };
  }

  /**
   * Build a single user's baseline from the last 30 days of ES data.
   * Uses only fields that actually exist in the ES mapping:
   *   collected_at, hostname, source_ip, user_principal, action, raw_message
   */
  private async buildBaselineForUser(
    userPrincipal: string,
    since: string,
  ): Promise<void> {
    const client = this.es.getClient();
    const now = new Date().toISOString();

    // Common filter reused across queries
    const userFilter = [
      { term: { user_principal: userPrincipal } },
      { range: { collected_at: { gte: since, lte: now } } },
    ];

    // ──────────────────────────────────────────────────────────
    // Query 1: Daily volume histogram
    // ES field: collected_at (date) → date_histogram by day
    // ──────────────────────────────────────────────────────────
    const dailyResult = await client.search({
      index: 'ctu-logs',
      size: 0,
      query: { bool: { filter: userFilter } },
      aggs: {
        by_day: {
          date_histogram: {
            field: 'collected_at',
            calendar_interval: 'day' as any,
            format: 'yyyy-MM-dd', // gives us key_as_string like "2026-06-15"
          },
        },
      },
    });

    // ──────────────────────────────────────────────────────────
    // Query 2: Hour-of-day distribution
    // ES field: collected_at (date) → date_histogram by hour
    // NOTE: Must use date_histogram with fixed_interval, NOT
    //       histogram with raw ms (which doesn't work on date fields)
    // ──────────────────────────────────────────────────────────
    const hourResult = await client.search({
      index: 'ctu-logs',
      size: 0,
      query: { bool: { filter: userFilter } },
      aggs: {
        by_hour: {
          date_histogram: {
            field: 'collected_at',
            fixed_interval: '1h' as any,
            min_doc_count: 1,
          },
        },
      },
    });

    // ──────────────────────────────────────────────────────────
    // Query 3: Known hosts and source IPs
    // ES fields: hostname (keyword), source_ip (ip)
    // ──────────────────────────────────────────────────────────
    const hostsResult = await client.search({
      index: 'ctu-logs',
      size: 0,
      query: { bool: { filter: userFilter } },
      aggs: {
        hosts: { terms: { field: 'hostname', size: 100 } },
        ips: { terms: { field: 'source_ip', size: 100 } },
      },
    });

    // ──────────────────────────────────────────────────────────
    // Query 4: File download activity
    // ES fields: action (keyword), raw_message (text)
    // We search BOTH exact action match AND text match in raw_message
    // ──────────────────────────────────────────────────────────
    const fileResult = await client.count({
      index: 'ctu-logs',
      query: {
        bool: {
          filter: [
            { term: { user_principal: userPrincipal } },
            { range: { collected_at: { gte: since, lte: now } } },
          ],
          should: [
            { term: { action: 'file_download' } },
            { term: { action: 'download' } },
            { match: { raw_message: 'file' } },
            { match: { raw_message: 'download' } },
          ],
          minimum_should_match: 1,
        },
      },
    });

    // ──────────────────────────────────────────────────────────
    // COMPUTE: Daily volume stats
    // From date_histogram by_day buckets
    // ──────────────────────────────────────────────────────────
    const dayBuckets =
      (dailyResult as any)?.aggregations?.by_day?.buckets ?? [];

    const dailyCounts: number[] = dayBuckets.map(
      (b: any) => b.doc_count as number,
    );

    const dailyVolumeAvg =
      dailyCounts.length > 0
        ? dailyCounts.reduce((a: number, b: number) => a + b, 0) /
          dailyCounts.length
        : 10;

    const dailyVolumeStd = this.computeStdDev(dailyCounts, dailyVolumeAvg);

    // ──────────────────────────────────────────────────────────
    // COMPUTE: Weekend ratio
    // Derived from daily histogram: each bucket has a timestamp key.
    // We check day-of-week from the bucket key to count weekend vs total.
    // NO separate ES query needed — we already have the data.
    // ──────────────────────────────────────────────────────────
    let weekendEventCount = 0;
    let totalEventCount = 0;

    for (const bucket of dayBuckets) {
      const count = bucket.doc_count as number;
      const keyStr = bucket.key_as_string as string; // "2026-06-15"

      if (keyStr) {
        const d = new Date(keyStr);
        const dayOfWeek = d.getDay(); // 0=Sun, 6=Sat
        if (dayOfWeek === 0 || dayOfWeek === 6) {
          weekendEventCount += count;
        }
      }
      totalEventCount += count;
    }

    // Fallback if no day data available
    const weekendRatio =
      totalEventCount > 0 ? weekendEventCount / totalEventCount : 0.05;

    // ──────────────────────────────────────────────────────────
    // COMPUTE: Active hours
    // From date_histogram by_hour buckets.
    // Each bucket key is a timestamp; we extract the UTC hour.
    // ──────────────────────────────────────────────────────────
    const hourBuckets =
      (hourResult as any)?.aggregations?.by_hour?.buckets ?? [];
    const activeHoursSet = new Set<number>();

    for (const bucket of hourBuckets) {
      const keyMs = bucket.key as number; // epoch millis
      const hour = new Date(keyMs).getUTCHours();
      activeHoursSet.add(hour);
    }

    const activeHours = Array.from(activeHoursSet).sort((a, b) => a - b);

    // Avg login hour = mean of active hours (approximate)
    const avgLoginHour =
      activeHours.length > 0
        ? activeHours.reduce((a, b) => a + b, 0) / activeHours.length
        : 9;
    const loginHourStd = this.computeStdDev(activeHours, avgLoginHour);

    // ──────────────────────────────────────────────────────────
    // COMPUTE: Known hosts and IPs
    // Straightforward terms aggregation results
    // ──────────────────────────────────────────────────────────
    const hostBuckets =
      (hostsResult as any)?.aggregations?.hosts?.buckets ?? [];
    const knownHosts: string[] = hostBuckets.map((b: any) => b.key as string);

    const ipBuckets = (hostsResult as any)?.aggregations?.ips?.buckets ?? [];
    const knownIps: string[] = ipBuckets.map((b: any) => b.key as string);

    // ──────────────────────────────────────────────────────────
    // COMPUTE: Average file downloads per session
    // From count of file-related events across 30 days
    // ──────────────────────────────────────────────────────────
    const fileDocCount = (fileResult as any)?.count ?? 0;
    const avgFileDownloads = Math.max(1, Math.round(fileDocCount / 30));

    // Average events per active hour
    const avgEventsPerHour =
      dailyCounts.length > 0
        ? Math.round(dailyVolumeAvg / Math.max(1, activeHours.length))
        : 5;

    // ──────────────────────────────────────────────────────────
    // BUILD & STORE baseline
    // ──────────────────────────────────────────────────────────
    const baseline: UebaBaseline = {
      active_hours:
        activeHours.length > 0
          ? activeHours
          : [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
      daily_volume_avg: Math.round(dailyVolumeAvg * 10) / 10,
      daily_volume_std: Math.round(dailyVolumeStd * 10) / 10,
      known_hosts: knownHosts,
      known_ips: knownIps,
      weekend_ratio: Math.round(weekendRatio * 100) / 100,
      avg_file_downloads: avgFileDownloads,
      avg_login_hour: Math.round(avgLoginHour * 10) / 10,
      login_hour_std: Math.round(loginHourStd * 10) / 10,
      avg_events_per_hour: avgEventsPerHour,
      daily_history: dailyCounts,
      computed_at: new Date().toISOString(),
    };

    // Store in PostgreSQL via Prisma
    await this.prisma.uebaProfile.upsert({
      where: { user_principal: userPrincipal },
      create: {
        user_principal: userPrincipal,
        risk_score: 15,
        baseline_data: baseline as any,
        last_calculated_at: new Date(),
        anomaly_count: 0,
      },
      update: {
        baseline_data: baseline as any,
        last_calculated_at: new Date(),
      },
    });

    this.logger.log(
      `Baseline built for ${userPrincipal}: ` +
        `${activeHours.length}h active, ${knownHosts.length} hosts, ` +
        `${Math.round(dailyVolumeAvg)} ev/day, ` +
        `weekend=${Math.round(weekendRatio * 100)}%`,
    );
  }

  private computeStdDev(values: number[], mean: number): number {
    if (values.length < 2) return 0;
    const sqDiffs = values.map((v) => (v - mean) ** 2);
    const variance = sqDiffs.reduce((a, b) => a + b, 0) / (values.length - 1);
    return Math.sqrt(variance);
  }
}
