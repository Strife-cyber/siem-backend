import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import PDFDocument from 'pdfkit';
import { Workbook } from 'exceljs';

export interface ReportRequest {
  type: 'pdf' | 'excel' | 'csv';
  start_date: string;
  end_date: string;
}

export interface ReportMeta {
  id: string;
  filename: string;
  type: string;
  size_bytes: number;
  created_at: string;
  expires_at: string;
}

@Injectable()
export class ReportGeneratorService {
  private readonly logger = new Logger(ReportGeneratorService.name);
  private readonly reportsDir: string;

  constructor() {
    this.reportsDir =
      process.env.REPORTS_DIR || path.join(process.cwd(), 'reports');
    fs.mkdirSync(path.join(this.reportsDir, 'pdf'), { recursive: true });
    fs.mkdirSync(path.join(this.reportsDir, 'xlsx'), { recursive: true });
    fs.mkdirSync(path.join(this.reportsDir, 'csv'), { recursive: true });
  }

  async generate(
    data: {
      overview: any;
      logs: any[];
      incidents: any[];
      auditTrails: any[];
      uebaProfiles: any[];
    },
    request: ReportRequest,
  ): Promise<ReportMeta> {
    switch (request.type) {
      case 'pdf':
        return this.generatePdf(data, request);
      case 'excel':
        return this.generateExcel(data, request);
      case 'csv':
        return this.generateCsv(data, request);
    }
  }

  // ══════════════════════════════════════════════
  //  PDF GENERATION
  // ══════════════════════════════════════════════

  /**
   * Ensures there's at least `needed` points of vertical space left on the
   * current page before drawing more content; otherwise starts a new page.
   * Centralizing this avoids rows silently running past the bottom margin.
   */
  private ensureSpace(doc: PDFKit.PDFDocument, needed: number): void {
    const bottom = doc.page.height - doc.page.margins.bottom;
    if (doc.y + needed > bottom) {
      doc.addPage();
    }
  }

  /** Safe divisor helper — guards against 0 (not just null/undefined) causing NaN widths. */
  private safeMax(value: number | undefined | null, fallback = 1): number {
    return value && value > 0 ? value : fallback;
  }

  private async generatePdf(
    data: any,
    request: ReportRequest,
  ): Promise<ReportMeta> {
    const id = crypto.randomUUID();
    const filename = `${request.start_date.slice(0, 10)}-report-${id.slice(0, 8)}.pdf`;
    const filePath = path.join(this.reportsDir, 'pdf', filename);

    const hasContent =
      data?.overview || data?.incidents?.length > 0 || data?.logs?.length > 0;
    if (!hasContent) {
      this.logger.warn(
        '[PDF] No data to generate report — creating summary-only PDF',
      );
    }

    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const writeStream = fs.createWriteStream(filePath);
    doc.pipe(writeStream);

    // Cleanup helper shared by every failure path below.
    const cleanupPartialFile = () => {
      try {
        writeStream.destroy();
      } catch {
        /* best-effort */
      }
      try {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch {
        /* best-effort */
      }
    };

    try {
      const { overview, incidents, auditTrails } = data;
      const severityDist: Record<string, number> =
        overview?.severity_distribution ?? {};
      const topSources = overview?.top_sources ?? [];
      const threatTypes = overview?.threat_types ?? [];
      const loginFailures = overview?.login_failures ?? [];
      const stats = overview?.stats ?? {};

      const sevColor = (s: string) =>
        ({
          CRITICAL: '#dc2626',
          HIGH: '#ea580c',
          WARNING: '#ca8a04',
          INFO: '#2563eb',
        })[s] ?? '#6b7280';

      // ────── PAGE 1: HEADER ──────
      doc
        .fontSize(24)
        .font('Helvetica-Bold')
        .text('Smart SIEM CTU', { align: 'center' });
      doc
        .fontSize(16)
        .font('Helvetica')
        .text('Security Report', { align: 'center' });
      doc.moveDown(0.5);
      doc
        .fontSize(10)
        .fillColor('#64748b')
        .text(
          `Period: ${request.start_date.slice(0, 10)} to ${request.end_date.slice(0, 10)}`,
          { align: 'center' },
        );
      doc.text(
        `Generated: ${new Date().toISOString().slice(0, 19).replace('T', ' ')} UTC`,
        { align: 'center' },
      );
      doc.moveDown(1);

      const status = (stats.system_status ?? 'OK').toUpperCase();
      const statusColor = status === 'OK' ? '#22c55e' : '#dc2626';
      this.ensureSpace(doc, 40);
      const statusBoxY = doc.y;
      doc.rect(50, statusBoxY, 495, 30).fill(statusColor);
      doc
        .fillColor('#ffffff')
        .fontSize(14)
        .font('Helvetica-Bold')
        .text(`System Status: ${status}`, 60, statusBoxY + 8);
      doc.fillColor('#000000');
      doc.y = statusBoxY + 40;

      doc.moveDown(1);

      // ────── PAGE 1: KEY METRICS ──────
      this.ensureSpace(doc, 30);
      doc.fontSize(14).font('Helvetica-Bold').text('Key Metrics');
      doc.moveDown(0.5);

      const totalCritical = severityDist.CRITICAL ?? 0;
      const totalHigh = severityDist.HIGH ?? 0;
      const openInc = stats.open_incidents ?? 0;
      const logsPerHour = stats.logs_per_hour ?? 0;

      const metrics: Array<{ label: string; value: number; color: string }> = [
        { label: 'Total Incidents', value: openInc, color: '#2563eb' },
        { label: 'Critical', value: totalCritical, color: '#dc2626' },
        { label: 'High', value: totalHigh, color: '#ea580c' },
        { label: 'Avg Logs/Hour', value: logsPerHour, color: '#6b7280' },
      ];

      const barX = 150;
      const barMaxWidth = 350;
      const maxMetric = this.safeMax(Math.max(...metrics.map((m) => m.value)));

      for (const m of metrics) {
        this.ensureSpace(doc, 24);
        const rowY = doc.y;
        doc
          .fontSize(10)
          .font('Helvetica')
          .fillColor('#374151')
          .text(m.label, 50, rowY + 2, { width: 90, lineBreak: false });
        const barW = (m.value / maxMetric) * barMaxWidth;
        doc.rect(barX, rowY, Math.max(barW, 1), 16).fill(m.color);
        doc
          .fillColor('#ffffff')
          .fontSize(9)
          .font('Helvetica-Bold')
          .text(String(m.value), barX + 4, rowY + 3, { lineBreak: false });
        doc.fillColor('#000000');
        doc.y = rowY + 24;
      }

      doc.moveDown(1);

      // ────── PAGE 2: SEVERITY DISTRIBUTION ──────
      doc.addPage();
      doc.fontSize(14).font('Helvetica-Bold').text('Severity Distribution');
      doc.moveDown(0.5);

      const totalSev = this.safeMax(
        Object.values(severityDist).reduce((a: number, b: number) => a + b, 0),
      );
      const barY = doc.y;
      let cumX = 50;
      for (const [sev, cnt] of Object.entries(severityDist)) {
        const pct = (cnt / totalSev) * 495;
        doc.rect(cumX, barY, Math.max(pct, 1), 24).fill(sevColor(sev));
        doc
          .fillColor('#ffffff')
          .fontSize(9)
          .font('Helvetica-Bold')
          .text(`${sev}: ${cnt}`, cumX + 4, barY + 6, { lineBreak: false });
        cumX += pct;
      }
      doc.fillColor('#000000');
      doc.y = barY + 24;
      doc.moveDown(2);

      // Table
      this.ensureSpace(doc, 24);
      doc.fontSize(10).font('Helvetica-Bold');
      const sevTableHeaderY = doc.y;
      doc.text('Severity', 50, sevTableHeaderY, { width: 100 });
      doc.text('Count', 200, sevTableHeaderY, { width: 80 });
      doc.text('Percentage', 300, sevTableHeaderY, { width: 100 });
      doc.y = sevTableHeaderY + 16;
      doc.rect(50, doc.y - 4, 495, 1).fill('#e5e7eb');

      doc.font('Helvetica');
      for (const [sev, cnt] of Object.entries(severityDist)) {
        this.ensureSpace(doc, 18);
        const rowY = doc.y + 4;
        doc.fillColor('#374151').text(sev, 50, rowY, { width: 100 });
        doc.text(String(cnt), 200, rowY, { width: 80 });
        doc.text(`${((cnt / totalSev) * 100).toFixed(1)}%`, 300, rowY, {
          width: 100,
        });
        doc.fillColor('#000000');
        doc.y = rowY + 14;
      }

      doc.moveDown(1);

      // ────── TOP SOURCES ──────
      this.ensureSpace(doc, 30);
      doc.fontSize(14).font('Helvetica-Bold').text('Top Source IPs');
      doc.moveDown(0.5);
      if (topSources.length > 0) {
        const maxSrc = this.safeMax(topSources[0]?.count);
        for (const s of topSources.slice(0, 10)) {
          this.ensureSpace(doc, 20);
          const rowY = doc.y;
          const w = (s.count / maxSrc) * 350;
          doc
            .fontSize(9)
            .font('Helvetica')
            .fillColor('#374151')
            .text(String(s.source_ip), 50, rowY + 2, {
              width: 120,
              lineBreak: false,
            });
          doc.rect(180, rowY, Math.max(w, 1), 14).fill('#3b82f6');
          doc
            .fillColor('#ffffff')
            .fontSize(8)
            .font('Helvetica-Bold')
            .text(String(s.count), 184, rowY + 3, { lineBreak: false });
          doc.fillColor('#000000');
          doc.y = rowY + 18;
        }
      } else {
        doc.fontSize(10).fillColor('#9ca3af').text('No data');
      }
      doc.fillColor('#000000');

      // ────── PAGE 3: THREAT TYPES + LOGIN FAILURES ──────
      doc.addPage();
      doc.fontSize(14).font('Helvetica-Bold').text('Threat Types');
      doc.moveDown(0.5);
      if (threatTypes.length > 0) {
        const maxThreat = this.safeMax(threatTypes[0]?.count);
        for (const t of threatTypes.slice(0, 10)) {
          this.ensureSpace(doc, 20);
          const rowY = doc.y;
          const w = (t.count / maxThreat) * 350;
          doc
            .fontSize(9)
            .font('Helvetica')
            .fillColor('#374151')
            .text(String(t.type), 50, rowY + 2, {
              width: 150,
              lineBreak: false,
            });
          doc.rect(210, rowY, Math.max(w, 1), 14).fill('#8b5cf6');
          doc
            .fillColor('#ffffff')
            .fontSize(8)
            .font('Helvetica-Bold')
            .text(String(t.count), 214, rowY + 3, { lineBreak: false });
          doc.fillColor('#000000');
          doc.y = rowY + 18;
        }
      } else {
        doc.fontSize(10).fillColor('#9ca3af').text('No data');
      }
      doc.fillColor('#000000');
      doc.moveDown(1.5);

      // Login failures table
      this.ensureSpace(doc, 30);
      doc.fontSize(14).font('Helvetica-Bold').text('Login Failures');
      doc.moveDown(0.5);
      if (loginFailures.length > 0) {
        doc.fontSize(9).font('Helvetica-Bold');
        const lfHeaderY = doc.y;
        doc.text('Period', 50, lfHeaderY, { width: 80 });
        doc.text('Count', 160, lfHeaderY, { width: 50 });
        doc.text('Threat Level', 230, lfHeaderY, { width: 100 });
        doc.text('Description', 340, lfHeaderY, { width: 200 });
        doc.y = lfHeaderY + 14;
        doc.rect(50, doc.y - 3, 495, 1).fill('#e5e7eb');
        doc.font('Helvetica');
        for (const f of loginFailures.slice(0, 12)) {
          this.ensureSpace(doc, 16);
          const lvlColor =
            f.threat_level === 'HIGH'
              ? '#dc2626'
              : f.threat_level === 'MEDIUM'
                ? '#ca8a04'
                : '#22c55e';
          const rowY = doc.y + 3;
          doc
            .fillColor('#374151')
            .text(String(f.label), 50, rowY, { width: 80 });
          doc.text(String(f.count), 160, rowY, { width: 50 });
          doc
            .fillColor(lvlColor)
            .text(String(f.threat_level), 230, rowY, { width: 100 });
          doc
            .fillColor('#374151')
            .text(String(f.description ?? '').slice(0, 50), 340, rowY, {
              width: 200,
            });
          doc.y = rowY + 13;
        }
      }
      doc.fillColor('#000000');

      // ────── PAGE 4: INCIDENTS + HUMAN ACTIONS ──────
      doc.addPage();
      doc.fontSize(14).font('Helvetica-Bold').text('Incidents');
      doc.moveDown(0.5);
      if (incidents.length > 0) {
        doc.fontSize(8).font('Helvetica-Bold');
        const incHeaderY = doc.y;
        doc.text('Severity', 50, incHeaderY, { width: 55 });
        doc.text('Rule', 115, incHeaderY, { width: 35 });
        doc.text('Summary', 160, incHeaderY, { width: 350 });
        doc.y = incHeaderY + 12;
        doc.rect(50, doc.y - 3, 495, 1).fill('#e5e7eb');
        doc.font('Helvetica');
        for (const inc of incidents.slice(0, 20)) {
          this.ensureSpace(doc, 14);
          const rowY = doc.y + 3;
          doc
            .fillColor(sevColor(String(inc.severity)))
            .text(String(inc.severity), 50, rowY, { width: 55 });
          doc
            .fillColor('#374151')
            .text(String(inc.rule_id ?? '-'), 115, rowY, { width: 35 });
          doc.text(String(inc.summary ?? '').slice(0, 90), 160, rowY, {
            width: 350,
          });
          doc.y = rowY + 10;
        }
      } else {
        doc.fontSize(10).fillColor('#9ca3af').text('No incidents');
      }
      doc.fillColor('#000000');
      doc.moveDown(1.5);

      // Human Actions
      this.ensureSpace(doc, 30);
      doc
        .fontSize(14)
        .font('Helvetica-Bold')
        .text('Human Actions (Audit Trail)');
      doc.moveDown(0.5);
      if (auditTrails.length > 0) {
        doc.fontSize(8).font('Helvetica-Bold');
        const atHeaderY = doc.y;
        doc.text('User', 50, atHeaderY, { width: 60 });
        doc.text('Action', 120, atHeaderY, { width: 120 });
        doc.text('Time', 250, atHeaderY, { width: 140 });
        doc.y = atHeaderY + 12;
        doc.rect(50, doc.y - 3, 495, 1).fill('#e5e7eb');
        doc.font('Helvetica');
        for (const t of auditTrails.slice(0, 15)) {
          this.ensureSpace(doc, 14);
          const performedAt = t.performed_at
            ? new Date(String(t.performed_at))
                .toISOString()
                .slice(0, 19)
                .replace('T', ' ')
            : '-';
          const rowY = doc.y + 3;
          doc
            .fillColor('#374151')
            .text(String(t.user_id ?? '-').slice(0, 8), 50, rowY, {
              width: 60,
            });
          doc.text(String(t.action ?? '-'), 120, rowY, { width: 120 });
          doc.text(performedAt, 250, rowY, { width: 140 });
          doc.y = rowY + 10;
        }
      } else {
        doc.fontSize(10).fillColor('#9ca3af').text('No audit trail entries');
      }
      doc.fillColor('#000000');
    } catch (err) {
      // A drawing call threw — the stream is still open, so make sure
      // it's torn down and the partial file removed before we surface the error.
      cleanupPartialFile();
      throw new Error(
        `PDF generation failed while rendering content: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }

    // Finalize PDF
    try {
      await new Promise<void>((resolve, reject) => {
        writeStream.on('finish', resolve);
        writeStream.on('close', resolve);
        writeStream.on('error', reject);
        doc.end();
      });
    } catch (err) {
      cleanupPartialFile();
      throw new Error(
        `PDF generation failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`PDF file was not created at ${filePath}`);
    }

    const stat = fs.statSync(filePath);
    if (stat.size < 100) {
      this.logger.warn(
        `[PDF] Generated file is very small (${stat.size} bytes) — possible empty PDF`,
      );
    }

    const meta: ReportMeta = {
      id,
      filename,
      type: 'pdf',
      size_bytes: stat.size,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    };
    this.logger.log(
      `[PDF] Generated: ${filename} (${(stat.size / 1024).toFixed(1)}KB)`,
    );
    return meta;
  }

  // ══════════════════════════════════════════════
  //  EXCEL GENERATION  (unchanged from original)
  // ══════════════════════════════════════════════

  private async generateExcel(
    data: any,
    request: ReportRequest,
  ): Promise<ReportMeta> {
    const id = crypto.randomUUID();
    const filename = `${request.start_date.slice(0, 10)}-events-${id.slice(0, 8)}.xlsx`;
    const filePath = path.join(this.reportsDir, 'xlsx', filename);
    const wb = new Workbook();
    wb.creator = 'Smart SIEM CTU';
    wb.created = new Date();

    const ws1 = wb.addWorksheet('Events');
    ws1.columns = [
      { header: 'Timestamp', key: 'collected_at', width: 22 },
      { header: 'Source IP', key: 'source_ip', width: 18 },
      { header: 'Destination IP', key: 'destination_ip', width: 18 },
      { header: 'Username', key: 'user_principal', width: 18 },
      { header: 'Event Type', key: 'event_taxonomy', width: 22 },
      { header: 'Severity', key: 'severity_label', width: 12 },
      { header: 'Machine', key: 'hostname', width: 20 },
      { header: 'Action', key: 'action', width: 16 },
      { header: 'Outcome', key: 'outcome', width: 12 },
      { header: 'Hash ID', key: 'ingestion_hash', width: 28 },
    ];

    const severityLabel = (s: number) =>
      s >= 7
        ? 'CRITICAL'
        : s >= 5
          ? 'HIGH'
          : s >= 3
            ? 'MEDIUM'
            : s >= 1
              ? 'LOW'
              : 'INFO';

    const headerRow = ws1.getRow(1);
    headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    headerRow.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF1E293B' },
    };
    headerRow.alignment = { horizontal: 'center' };

    for (const log of data.logs.slice(0, 100000)) {
      ws1.addRow({
        collected_at: log.collected_at,
        source_ip: log.source_ip,
        destination_ip: log.destination_ip ?? '',
        user_principal: log.user_principal ?? '',
        event_taxonomy: log.event_taxonomy,
        severity_label: severityLabel(Number(log.severity)),
        hostname: log.hostname,
        action: log.action,
        outcome: log.outcome ?? '',
        ingestion_hash: (log.ingestion_hash ?? '').slice(0, 16),
      });
    }

    const ws2 = wb.addWorksheet('Summary');
    const overview = data.overview ?? {};
    const severityDist = overview.severity_distribution ?? {};

    ws2.addRow(['Metric', 'Value']);
    ws2.addRow(['Total Incidents', data.incidents.length]);
    ws2.addRow(['Total Logs', data.logs.length]);
    ws2.addRow(['Critical', severityDist.CRITICAL ?? 0]);
    ws2.addRow(['High', severityDist.HIGH ?? 0]);
    ws2.addRow(['Warning', severityDist.WARNING ?? 0]);
    ws2.addRow(['Info', severityDist.INFO ?? 0]);
    ws2.addRow(['Avg Logs/Hour', overview.stats?.logs_per_hour ?? 0]);
    ws2.addRow(['System Status', overview.stats?.system_status ?? 'OK']);

    ws2.getRow(1).font = { bold: true };

    try {
      await wb.xlsx.writeFile(filePath);
    } catch (err) {
      try {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch {
        /* best-effort cleanup */
      }
      throw new Error(
        `Excel generation failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`Excel file was not created at ${filePath}`);
    }

    const stat = fs.statSync(filePath);
    const meta: ReportMeta = {
      id,
      filename,
      type: 'excel',
      size_bytes: stat.size,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    };
    this.logger.log(
      `[Excel] Generated: ${filename} (${(stat.size / 1024).toFixed(1)}KB)`,
    );
    return meta;
  }

  // ══════════════════════════════════════════════
  //  CSV GENERATION  (unchanged from original)
  // ══════════════════════════════════════════════

  private async generateCsv(
    data: any,
    request: ReportRequest,
  ): Promise<ReportMeta> {
    const id = crypto.randomUUID();
    const filename = `${request.start_date.slice(0, 10)}-events-${id.slice(0, 8)}.csv`;
    const filePath = path.join(this.reportsDir, 'csv', filename);

    const severityLabel = (s: number) =>
      s >= 7
        ? 'CRITICAL'
        : s >= 5
          ? 'HIGH'
          : s >= 3
            ? 'MEDIUM'
            : s >= 1
              ? 'LOW'
              : 'INFO';

    const escape = (v: any) => {
      const s = String(v ?? '');
      return s.includes(',') || s.includes('"')
        ? `"${s.replace(/"/g, '""')}"`
        : s;
    };

    const header =
      'Timestamp,Source IP,Destination IP,Username,Event Type,Severity,Machine,Action,Outcome,Hash ID\n';
    const lines = data.logs
      .slice(0, 200000)
      .map((log: any) =>
        [
          log.collected_at,
          log.source_ip,
          log.destination_ip ?? '',
          log.user_principal ?? '',
          log.event_taxonomy,
          severityLabel(Number(log.severity)),
          log.hostname,
          log.action,
          log.outcome ?? '',
          (log.ingestion_hash ?? '').slice(0, 16),
        ]
          .map(escape)
          .join(','),
      )
      .join('\n');

    fs.writeFileSync(filePath, header + lines, 'utf-8');

    const stat = fs.statSync(filePath);
    const meta: ReportMeta = {
      id,
      filename,
      type: 'csv',
      size_bytes: stat.size,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    };
    this.logger.log(
      `[CSV] Generated: ${filename} (${(stat.size / 1024).toFixed(1)}KB)`,
    );
    return meta;
  }

  /**
   * Resolves a report filename to a full path. Sanitized against traversal:
   * only a bare filename (no path separators, no "..") is accepted, since
   * this is joined with a trusted base directory.
   */
  getFilePath(filename: string): string | null {
    const base = path.basename(filename);
    if (base !== filename || base.includes('..')) {
      this.logger.warn(`[Security] Rejected suspicious filename: ${filename}`);
      return null;
    }

    const candidates = [
      path.join(this.reportsDir, 'pdf', base),
      path.join(this.reportsDir, 'xlsx', base),
      path.join(this.reportsDir, 'csv', base),
    ];
    for (const fp of candidates) {
      if (fs.existsSync(fp)) return fp;
    }
    return null;
  }

  listReports(): { pdf: string[]; xlsx: string[]; csv: string[] } {
    const listDir = (dir: string, ext: string) => {
      const full = path.join(this.reportsDir, dir);
      if (!fs.existsSync(full)) return [];
      return fs.readdirSync(full).filter((f) => f.endsWith(ext));
    };
    return {
      pdf: listDir('pdf', '.pdf'),
      xlsx: listDir('xlsx', '.xlsx'),
      csv: listDir('csv', '.csv'),
    };
  }

  cleanup(): void {
    const dirs = ['pdf', 'xlsx', 'csv'];
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    for (const dir of dirs) {
      const fullDir = path.join(this.reportsDir, dir);
      if (!fs.existsSync(fullDir)) continue;
      for (const f of fs.readdirSync(fullDir)) {
        const fp = path.join(fullDir, f);
        const stat = fs.statSync(fp);
        if (stat.mtimeMs < cutoff) {
          fs.unlinkSync(fp);
          this.logger.log(`[Cleanup] Deleted old report: ${f}`);
        }
      }
    }
  }
}
