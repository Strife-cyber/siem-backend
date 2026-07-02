import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const PDF = require('pdfkit');
const ExcelJS = require('exceljs');

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

  private async generatePdf(
    data: any,
    request: ReportRequest,
  ): Promise<ReportMeta> {
    const id = crypto.randomUUID();
    const filename = `${request.start_date.slice(0, 10)}-report-${id.slice(0, 8)}.pdf`;
    const filePath = path.join(this.reportsDir, 'pdf', filename);
    const doc = new PDF({ size: 'A4', margin: 50 });

    const writeStream = fs.createWriteStream(filePath);
    doc.pipe(writeStream);

    const { overview, incidents, logs, auditTrails, uebaProfiles } = data;
    const severityDist: Record<string, number> =
      overview?.severity_distribution ?? {};
    const topSources = overview?.top_sources ?? [];
    const threatTypes = overview?.threat_types ?? [];
    const timeline = overview?.events_timeline ?? [];
    const loginFailures = overview?.login_failures ?? [];
    const stats = overview?.stats ?? {};

    // Helper: severity color
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

    // System status box
    const status = (stats.system_status ?? 'OK').toUpperCase();
    const statusColor = status === 'OK' ? '#22c55e' : '#dc2626';
    doc.rect(50, doc.y, 495, 30).fill(statusColor);
    doc
      .fillColor('#ffffff')
      .fontSize(14)
      .font('Helvetica-Bold')
      .text(`System Status: ${status}`, 60, doc.y - 22);
    doc.fillColor('#000000');

    doc.moveDown(2);

    // ────── PAGE 1: KEY METRICS ──────
    doc.fontSize(14).font('Helvetica-Bold').text('Key Metrics');
    doc.moveDown(0.5);

    const totalCritical = severityDist.CRITICAL ?? 0;
    const totalHigh = severityDist.HIGH ?? 0;
    const openInc = stats.open_incidents ?? 0;
    const logsPerHour = stats.logs_per_hour ?? 0;

    const metrics = [
      { label: 'Total Incidents', value: openInc, color: '#2563eb' },
      { label: 'Critical', value: totalCritical, color: '#dc2626' },
      { label: 'High', value: totalHigh, color: '#ea580c' },
      { label: 'Avg Logs/Hour', value: logsPerHour, color: '#6b7280' },
    ];

    const barX = 150;
    const barMaxWidth = 350;
    const maxMetric = Math.max(...metrics.map((m) => m.value), 1);
    for (const m of metrics) {
      doc
        .fontSize(10)
        .font('Helvetica')
        .fillColor('#374151')
        .text(m.label, 50, doc.y + 2, { width: 90 });
      const barW = (m.value / maxMetric) * barMaxWidth;
      doc.rect(barX, doc.y - 4, Math.max(barW, 1), 16).fill(m.color);
      doc
        .fillColor('#ffffff')
        .fontSize(9)
        .font('Helvetica-Bold')
        .text(String(m.value), barX + 4, doc.y - 1);
      doc.fillColor('#000000');
      doc.moveDown(1.5);
    }

    doc.moveDown(1);

    // ────── PAGE 2: SEVERITY DISTRIBUTION ──────
    doc.addPage();
    doc.fontSize(14).font('Helvetica-Bold').text('Severity Distribution');
    doc.moveDown(0.5);

    const totalSev = Math.max(
      Object.values(severityDist).reduce(
        (a: number, b: any) => a + (b as number),
        0,
      ),
      1,
    );
    let cumX = 50;
    for (const [sev, cnt] of Object.entries(severityDist)) {
      const pct = ((cnt as number) / totalSev) * 495;
      doc.rect(cumX, doc.y, Math.max(pct, 1), 24).fill(sevColor(sev));
      doc
        .fillColor('#ffffff')
        .fontSize(9)
        .font('Helvetica-Bold')
        .text(`${sev}: ${cnt}`, cumX + 4, doc.y + 6);
      cumX += pct;
    }
    doc.fillColor('#000000');
    doc.moveDown(3);

    // Table
    doc.fontSize(10).font('Helvetica-Bold');
    doc.text('Severity', 50, doc.y, { width: 100 });
    doc.text('Count', 200, doc.y - 12, { width: 80 });
    doc.text('Percentage', 300, doc.y - 12, { width: 100 });
    doc.moveDown(0.3);
    doc.rect(50, doc.y - 4, 495, 1).fill('#e5e7eb');

    doc.font('Helvetica');
    for (const [sev, cnt] of Object.entries(severityDist)) {
      doc.fillColor('#374151').text(sev, 50, doc.y + 4, { width: 100 });
      doc.text(String(cnt), 200, doc.y - 12, { width: 80 });
      doc.text(
        `${(((cnt as number) / totalSev) * 100).toFixed(1)}%`,
        300,
        doc.y - 12,
        { width: 100 },
      );
      doc.fillColor('#000000');
      doc.moveDown(0.5);
    }

    doc.moveDown(1);

    // ────── TOP SOURCES ──────
    doc.fontSize(14).font('Helvetica-Bold').text('Top Source IPs');
    doc.moveDown(0.5);
    if (topSources.length > 0) {
      const maxSrc = topSources[0]?.count ?? 1;
      for (const s of topSources.slice(0, 10)) {
        const w = (s.count / maxSrc) * 350;
        doc
          .fontSize(9)
          .font('Helvetica')
          .fillColor('#374151')
          .text(s.source_ip, 50, doc.y + 2, { width: 120 });
        doc.rect(180, doc.y - 4, Math.max(w, 1), 14).fill('#3b82f6');
        doc
          .fillColor('#ffffff')
          .fontSize(8)
          .font('Helvetica-Bold')
          .text(String(s.count), 184, doc.y - 1);
        doc.fillColor('#000000');
        doc.moveDown(1.3);
      }
    } else {
      doc.fontSize(10).fillColor('#9ca3af').text('No data');
    }
    doc.fillColor('#000000');

    // ────── PAGE 3: THREAT TYPES + TIMELINE ──────
    doc.addPage();
    doc.fontSize(14).font('Helvetica-Bold').text('Threat Types');
    doc.moveDown(0.5);
    if (threatTypes.length > 0) {
      const maxThreat = threatTypes[0]?.count ?? 1;
      for (const t of threatTypes.slice(0, 10)) {
        const w = (t.count / maxThreat) * 350;
        doc
          .fontSize(9)
          .font('Helvetica')
          .fillColor('#374151')
          .text(t.type, 50, doc.y + 2, { width: 150 });
        doc.rect(210, doc.y - 4, Math.max(w, 1), 14).fill('#8b5cf6');
        doc
          .fillColor('#ffffff')
          .fontSize(8)
          .font('Helvetica-Bold')
          .text(String(t.count), 214, doc.y - 1);
        doc.fillColor('#000000');
        doc.moveDown(1.3);
      }
    } else {
      doc.fontSize(10).fillColor('#9ca3af').text('No data');
    }
    doc.fillColor('#000000');
    doc.moveDown(1.5);

    // Login failures table
    doc.fontSize(14).font('Helvetica-Bold').text('Login Failures');
    doc.moveDown(0.5);
    if (loginFailures.length > 0) {
      doc.fontSize(9).font('Helvetica-Bold');
      doc.text('Period', 50, doc.y, { width: 80 });
      doc.text('Count', 160, doc.y - 12, { width: 50 });
      doc.text('Threat Level', 230, doc.y - 12, { width: 100 });
      doc.text('Description', 340, doc.y - 12, { width: 200 });
      doc.moveDown(0.2);
      doc.rect(50, doc.y - 3, 495, 1).fill('#e5e7eb');
      doc.font('Helvetica');
      for (const f of loginFailures.slice(0, 12)) {
        const lvlColor =
          f.threat_level === 'HIGH'
            ? '#dc2626'
            : f.threat_level === 'MEDIUM'
              ? '#ca8a04'
              : '#22c55e';
        doc.fillColor('#374151').text(f.label, 50, doc.y + 3, { width: 80 });
        doc.text(String(f.count), 160, doc.y - 12, { width: 50 });
        doc
          .fillColor(lvlColor)
          .text(f.threat_level, 230, doc.y - 12, { width: 100 });
        doc
          .fillColor('#374151')
          .text(f.description.slice(0, 50), 340, doc.y - 12, { width: 200 });
        doc.moveDown(0.8);
      }
    }
    doc.fillColor('#000000');

    // ────── PAGE 4: INCIDENTS + HUMAN ACTIONS ──────
    doc.addPage();
    doc.fontSize(14).font('Helvetica-Bold').text('Incidents');
    doc.moveDown(0.5);
    if (incidents.length > 0) {
      doc.fontSize(8).font('Helvetica-Bold');
      doc.text('Severity', 50, doc.y, { width: 55 });
      doc.text('Rule', 115, doc.y - 12, { width: 35 });
      doc.text('Summary', 160, doc.y - 12, { width: 350 });
      doc.moveDown(0.2);
      doc.rect(50, doc.y - 3, 495, 1).fill('#e5e7eb');
      doc.font('Helvetica');
      for (const inc of incidents.slice(0, 20)) {
        doc
          .fillColor(sevColor(inc.severity))
          .text(inc.severity, 50, doc.y + 3, { width: 55 });
        doc
          .fillColor('#374151')
          .text(inc.rule_id ?? '-', 115, doc.y - 12, { width: 35 });
        doc.text((inc.summary ?? '').slice(0, 90), 160, doc.y - 12, {
          width: 350,
        });
        doc.moveDown(0.6);
      }
    } else {
      doc.fontSize(10).fillColor('#9ca3af').text('No incidents');
    }
    doc.fillColor('#000000');
    doc.moveDown(1.5);

    // Human Actions
    doc.fontSize(14).font('Helvetica-Bold').text('Human Actions (Audit Trail)');
    doc.moveDown(0.5);
    if (auditTrails.length > 0) {
      doc.fontSize(8).font('Helvetica-Bold');
      doc.text('User', 50, doc.y, { width: 60 });
      doc.text('Action', 120, doc.y - 12, { width: 120 });
      doc.text('Time', 250, doc.y - 12, { width: 140 });
      doc.moveDown(0.2);
      doc.rect(50, doc.y - 3, 495, 1).fill('#e5e7eb');
      doc.font('Helvetica');
      for (const t of auditTrails.slice(0, 15)) {
        doc
          .fillColor('#374151')
          .text(String(t.user_id ?? '-').slice(0, 8), 50, doc.y + 3, {
            width: 60,
          });
        doc.text(t.action ?? '-', 120, doc.y - 12, { width: 120 });
        doc.text(
          t.performed_at
            ? new Date(t.performed_at)
                .toISOString()
                .slice(0, 19)
                .replace('T', ' ')
            : '-',
          250,
          doc.y - 12,
          { width: 140 },
        );
        doc.moveDown(0.6);
      }
    } else {
      doc.fontSize(10).fillColor('#9ca3af').text('No audit trail entries');
    }
    doc.fillColor('#000000');

    // Finalize PDF
    doc.end();
    await new Promise<void>((resolve) => writeStream.on('finish', resolve));

    const stat = fs.statSync(filePath);
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
  //  EXCEL GENERATION
  // ══════════════════════════════════════════════

  private async generateExcel(
    data: any,
    request: ReportRequest,
  ): Promise<ReportMeta> {
    const id = crypto.randomUUID();
    const filename = `${request.start_date.slice(0, 10)}-events-${id.slice(0, 8)}.xlsx`;
    const filePath = path.join(this.reportsDir, 'xlsx', filename);
    const wb = new ExcelJS.Workbook();
    wb.creator = 'Smart SIEM CTU';
    wb.created = new Date();

    // ────── SHEET 1: Raw Events ──────
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

    // Style header row
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
        severity_label: severityLabel(log.severity),
        hostname: log.hostname,
        action: log.action,
        outcome: log.outcome ?? '',
        ingestion_hash: (log.ingestion_hash ?? '').slice(0, 16),
      });
    }

    // ────── SHEET 2: Summary ──────
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

    // Style summary
    ws2.getRow(1).font = { bold: true };

    await wb.xlsx.writeFile(filePath);

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
  //  CSV GENERATION
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
          severityLabel(log.severity),
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

  getFilePath(filename: string): string | null {
    const candidates = [
      path.join(this.reportsDir, 'pdf', filename),
      path.join(this.reportsDir, 'xlsx', filename),
      path.join(this.reportsDir, 'csv', filename),
    ];
    for (const fp of candidates) {
      if (fs.existsSync(fp)) return fp;
    }
    return null;
  }

  listReports(): { pdf: string[]; xlsx: string[]; csv: string[] } {
    return {
      pdf: fs
        .readdirSync(path.join(this.reportsDir, 'pdf'))
        .filter((f) => f.endsWith('.pdf')),
      xlsx: fs
        .readdirSync(path.join(this.reportsDir, 'xlsx'))
        .filter((f) => f.endsWith('.xlsx')),
      csv: fs
        .readdirSync(path.join(this.reportsDir, 'csv'))
        .filter((f) => f.endsWith('.csv')),
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
