import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { PrismaService } from '../prisma/prisma.service';
import { DashboardService } from '../dashboard/dashboard.service';
import { MailService } from '../mail/mail.service';
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
    private readonly mail: MailService,
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
            include: { user: { select: { role: true } } },
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

      // Auto-send PDF report to configured admins
      if (meta.type === 'pdf') {
        this.sendReportEmail(meta, request).catch((err) =>
          this.logger.error(
            `[Reports] Failed to email report ${meta.filename}: ${err.message}`,
          ),
        );
      }
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

  /** Send the generated PDF report to configured admin recipients */
  private async sendReportEmail(
    meta: ReportMeta,
    request: ReportRequest,
  ): Promise<void> {
    const recipients = (process.env.ALERT_EMAIL_TO || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (recipients.length === 0) {
      this.logger.log(
        '[Reports] No ALERT_EMAIL_TO configured — skipping report email',
      );
      return;
    }

    const filePath = this.generator.getFilePath(meta.filename);
    if (!filePath || !fs.existsSync(filePath)) {
      this.logger.warn(
        `[Reports] Report file not found for email: ${meta.filename}`,
      );
      return;
    }

    const period = `${request.start_date.slice(0, 10)} — ${request.end_date.slice(0, 10)}`;
    const reportName = meta.filename.replace('.pdf', '');

    await this.mail.sendEmailWithAttachment({
      to: recipients,
      subject: `[SIEM] Rapport de Sécurité — ${period}`,
      html: `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: 'Helvetica Neue', Arial, sans-serif; background: #f8fafc; padding: 24px;">
  <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
    <div style="background: #0f172a; padding: 24px 32px;">
      <h1 style="color: #dbeafe; margin: 0; font-size: 20px;">SMART SIEM CTU</h1>
      <p style="color: #94a3b8; margin: 4px 0 0;">Rapport de Sécurité</p>
    </div>
    <div style="padding: 32px;">
      <h2 style="color: #0f172a; margin: 0 0 8px;">Rapport prêt</h2>
      <p style="color: #475569; margin: 0 0 20px;">
        Le rapport de sécurité pour la période <strong>${period}</strong> a été généré avec succès.
      </p>
      <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
        <tr>
          <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; color: #64748b;">Fichier</td>
          <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; color: #0f172a; font-weight: bold;">${meta.filename}</td>
        </tr>
        <tr>
          <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; color: #64748b;">Taille</td>
          <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; color: #0f172a; font-weight: bold;">${(meta.size_bytes / 1024).toFixed(1)} KB</td>
        </tr>
        <tr>
          <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; color: #64748b;">Période</td>
          <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; color: #0f172a; font-weight: bold;">${period}</td>
        </tr>
      </table>
      <p style="color: #94a3b8; font-size: 12px; margin: 0;">
        Le rapport PDF est joint à cet email.
      </p>
    </div>
    <div style="background: #f1f5f9; padding: 12px 32px; text-align: center;">
      <p style="color: #94a3b8; font-size: 11px; margin: 0;">
        Document Confidentiel — Smart SIEM CTU &copy; ${new Date().getFullYear()}
      </p>
    </div>
  </div>
</body>
</html>`,
      text: `Smart SIEM CTU — Rapport de Sécurité\n\nPériode: ${period}\nFichier: ${meta.filename}\nTaille: ${(meta.size_bytes / 1024).toFixed(1)} KB\n\nLe rapport PDF est joint à cet email.\n\nDocument Confidentiel`,
      attachment: { filename: meta.filename, path: filePath },
    });
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
