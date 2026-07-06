import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { PrismaService } from '../prisma/prisma.service';
import { DashboardService } from '../dashboard/dashboard.service';
import {
  ReportGeneratorService,
  type ReportMeta,
  type ReportRequest,
} from './report-generator.service';

@Injectable()
export class ReportsService {
  private readonly logger = new Logger(ReportsService.name);
  private readonly pendingJobs = new Map<
    string,
    { status: string; meta?: ReportMeta }
  >();

  constructor(
    private readonly es: ElasticsearchService,
    private readonly prisma: PrismaService,
    private readonly dashboard: DashboardService,
    private readonly generator: ReportGeneratorService,
  ) {}

  async generate(
    request: ReportRequest,
  ): Promise<{ job_id: string; status: string }> {
    const jobId = crypto.randomUUID();
    this.pendingJobs.set(jobId, { status: 'generating' });

    // Fire and forget — generate in background
    this.doGenerate(jobId, request).catch((err) => {
      this.logger.error(`Report generation failed: ${err.message}`);
      this.pendingJobs.set(jobId, { status: 'failed' });
    });

    return { job_id: jobId, status: 'generating' };
  }

  private async doGenerate(
    jobId: string,
    request: ReportRequest,
  ): Promise<void> {
    try {
      const dateFrom = new Date(request.start_date);
      const dateTo = new Date(request.end_date);

      // Compute dashboard interval from the date range
      const rangeHours =
        (dateTo.getTime() - dateFrom.getTime()) / (1000 * 60 * 60);
      const overviewInterval =
        rangeHours <= 2
          ? '1h'
          : rangeHours <= 48
            ? '24h'
            : rangeHours <= 336
              ? '7d'
              : '30d';

      // Gather all data in parallel
      const [overview, logs, incidents, auditTrails, uebaProfiles] =
        await Promise.all([
          this.dashboard.getOverview(overviewInterval).catch(() => ({})),
          this.fetchLogs(dateFrom, dateTo),
          this.prisma.incident.findMany({
            where: { triggered_at: { gte: dateFrom, lte: dateTo } },
            orderBy: { triggered_at: 'desc' },
            take: 500,
          }),
          this.prisma.auditTrail.findMany({
            where: { performed_at: { gte: dateFrom, lte: dateTo } },
            orderBy: { performed_at: 'desc' },
            take: 200,
          }),
          this.prisma.uebaProfile.findMany({
            orderBy: { risk_score: 'desc' },
            take: 50,
          }),
        ]);

      const meta = await this.generator.generate(
        { overview, logs, incidents, auditTrails, uebaProfiles },
        request,
      );
      this.pendingJobs.set(jobId, { status: 'ready', meta });
    } catch (err: any) {
      this.pendingJobs.set(jobId, { status: 'failed' });
      throw err;
    }
  }

  getJobStatus(jobId: string): { status: string; meta?: ReportMeta } | null {
    return this.pendingJobs.get(jobId) ?? null;
  }

  download(jobId: string): { filePath: string; filename: string } | null {
    const job = this.pendingJobs.get(jobId);
    if (!job?.meta) return null;
    const filePath = this.generator.getFilePath(job.meta.filename);
    if (!filePath) return null;
    return { filePath, filename: job.meta.filename };
  }

  listReports() {
    return this.generator.listReports();
  }

  async cleanup() {
    this.generator.cleanup();
  }

  private async fetchLogs(dateFrom: Date, dateTo: Date): Promise<any[]> {
    const logs: any[] = [];
    let searchAfter: any = null;
    const size = 1000;

    try {
      while (logs.length < 100000) {
        const body: any = {
          index: 'ctu-logs',
          size,
          _source: true,
          sort: [{ collected_at: { order: 'asc' } }],
          query: {
            range: {
              collected_at: {
                gte: dateFrom.toISOString(),
                lte: dateTo.toISOString(),
              },
            },
          },
        };
        if (searchAfter) body.search_after = searchAfter;

        const result = await this.es
          .getClient()
          .search(body)
          .then((r: any) => r);
        const hits = result?.hits?.hits ?? [];
        if (hits.length === 0) break;

        for (const hit of hits) {
          logs.push(hit._source);
        }

        const last = hits[hits.length - 1];
        searchAfter = last.sort;
      }
    } catch (err: any) {
      this.logger.warn(
        `Partial log fetch: ${logs.length} logs retrieved before error: ${err.message}`,
      );
    }

    return logs;
  }
}
