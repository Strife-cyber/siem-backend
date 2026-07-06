import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import { Workbook, Worksheet } from 'exceljs';
import { LatexReportService } from './latex-report.service';

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

function fmtDate(d?: string | Date): string {
  if (!d) return '-';
  const date = typeof d === 'string' ? new Date(d) : d;
  if (Number.isNaN(date.getTime())) return '-';
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function fmtDateShort(d?: string | Date): string {
  if (!d) return '-';
  const date = typeof d === 'string' ? new Date(d) : d;
  if (Number.isNaN(date.getTime())) return String(d).slice(0, 10);
  return date.toISOString().slice(0, 10);
}

@Injectable()
export class ReportGeneratorService {
  private readonly logger = new Logger(ReportGeneratorService.name);
  private readonly reportsDir: string;

  constructor(private readonly latex: LatexReportService) {
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
  //  PDF GENERATION — LaTeX
  // ══════════════════════════════════════════════

  private async generatePdf(
    data: any,
    request: ReportRequest,
  ): Promise<ReportMeta> {
    const lateXMeta = await this.latex.generate(data, request);

    const meta: ReportMeta = {
      ...lateXMeta,
      type: 'pdf',
    };
    this.logger.log(
      `[PDF] Generated: ${meta.filename} (${(meta.size_bytes / 1024).toFixed(1)} KB) — LaTeX`,
    );
    return meta;
  }

  // ══════════════════════════════════════════════
  //  EXCEL GENERATION
  // ══════════════════════════════════════════════

  private severityLabel(s: number): string {
    return s >= 7
      ? 'CRITICAL'
      : s >= 5
        ? 'HIGH'
        : s >= 3
          ? 'MEDIUM'
          : s >= 1
            ? 'LOW'
            : 'INFO';
  }

  private styleHeaderRow(ws: Worksheet, rowNum = 1) {
    const row = ws.getRow(rowNum);
    row.eachCell((cell) => {
      cell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
      cell.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF0F172A' },
      };
      cell.alignment = { vertical: 'middle', horizontal: 'center' };
      cell.border = {
        top: { style: 'thin', color: { argb: 'FF334155' } },
        bottom: { style: 'thin', color: { argb: 'FF334155' } },
      };
    });
    row.height = 20;
  }

  private applyZebraAndBorders(
    ws: Worksheet,
    firstDataRow: number,
    lastDataRow: number,
  ) {
    for (let r = firstDataRow; r <= lastDataRow; r++) {
      const row = ws.getRow(r);
      const isAlt = (r - firstDataRow) % 2 === 1;
      row.eachCell({ includeEmpty: true }, (cell) => {
        if (isAlt) {
          cell.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFF8FAFC' },
          };
        }
        cell.border = {
          bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } },
        };
        cell.alignment = { ...cell.alignment, vertical: 'middle' };
      });
    }
  }

  private severityFillArgb(label: string): string {
    return (
      {
        CRITICAL: 'FFFEE2E2',
        HIGH: 'FFFFEDD5',
        MEDIUM: 'FFFEF9C3',
        LOW: 'FFDBEAFE',
        INFO: 'FFDBEAFE',
      }[label] ?? 'FFF1F5F9'
    );
  }

  private severityFontArgb(label: string): string {
    return (
      {
        CRITICAL: 'FF991B1B',
        HIGH: 'FF9A3412',
        MEDIUM: 'FF854D0E',
        LOW: 'FF1E40AF',
        INFO: 'FF1E40AF',
      }[label] ?? 'FF334155'
    );
  }

  private async generateExcel(
    data: any,
    request: ReportRequest,
  ): Promise<ReportMeta> {
    const id = crypto.randomUUID();
    const filename = `${request.start_date.slice(0, 10)}-events-${id.slice(0, 8)}.xlsx`;
    const filePath = path.join(this.reportsDir, 'xlsx', filename);
    const period = `${fmtDateShort(request.start_date)} to ${fmtDateShort(request.end_date)}`;

    const wb = new Workbook();
    wb.creator = 'Smart SIEM CTU';
    wb.created = new Date();

    // ────── SUMMARY SHEET (first, so it's what opens by default) ──────
    const ws2 = wb.addWorksheet('Summary', {
      properties: { tabColor: { argb: 'FF2563EB' } },
      views: [{ showGridLines: false }],
    });
    ws2.columns = [{ width: 4 }, { width: 30 }, { width: 18 }, { width: 40 }];

    ws2.mergeCells('B2:D2');
    const titleCell = ws2.getCell('B2');
    titleCell.value = 'Smart SIEM CTU — Security Report';
    titleCell.font = { bold: true, size: 16, color: { argb: 'FF0F172A' } };

    ws2.mergeCells('B3:D3');
    const subCell = ws2.getCell('B3');
    subCell.value = `Reporting period: ${period}  •  Generated ${fmtDate(new Date())} UTC`;
    subCell.font = { size: 10, color: { argb: 'FF64748B' } };

    const overview = data.overview ?? {};
    const severityDist: Record<string, number> =
      overview.severity_distribution ?? {};
    const stats = overview.stats ?? {};

    ws2.mergeCells('B5:D5');
    ws2.getCell('B5').value = 'Key Metrics';
    ws2.getCell('B5').font = {
      bold: true,
      size: 12,
      color: { argb: 'FF0F172A' },
    };

    const metricRows: Array<[string, number | string]> = [
      ['Total Incidents', data.incidents.length],
      ['Total Log Events', data.logs.length],
      ['Critical Events', severityDist.CRITICAL ?? 0],
      ['High Severity Events', severityDist.HIGH ?? 0],
      ['Warning Events', severityDist.WARNING ?? 0],
      ['Info Events', severityDist.INFO ?? 0],
      ['Avg Logs / Hour', stats.logs_per_hour ?? 0],
      ['System Status', stats.system_status ?? 'OK'],
    ];

    let r = 6;
    for (const [label, value] of metricRows) {
      ws2.getCell(`B${r}`).value = label;
      ws2.getCell(`B${r}`).font = { color: { argb: 'FF334155' } };
      ws2.mergeCells(`C${r}:D${r}`);
      const valCell = ws2.getCell(`C${r}`);
      valCell.value = value;
      valCell.font = { bold: true, color: { argb: 'FF0F172A' } };
      valCell.alignment = { horizontal: 'left' };
      ws2.getRow(r).eachCell({ includeEmpty: false }, (c) => {
        c.border = { bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } } };
      });
      r++;
    }

    r += 1;
    ws2.mergeCells(`B${r}:D${r}`);
    ws2.getCell(`B${r}`).value = 'Severity Breakdown';
    ws2.getCell(`B${r}`).font = {
      bold: true,
      size: 12,
      color: { argb: 'FF0F172A' },
    };
    r++;
    const sevHeaderRow = r;
    ws2.getCell(`B${r}`).value = 'Severity';
    ws2.getCell(`C${r}`).value = 'Count';
    ws2.getCell(`D${r}`).value = 'Share';
    this.styleHeaderRow(ws2, sevHeaderRow);
    // header only spans B:D here, blank col A stays untouched
    ws2.getCell(`A${sevHeaderRow}`).fill = undefined as any;
    r++;
    const totalSev =
      Object.values(severityDist).reduce((a, b) => a + b, 0) || 1;
    const sevFirstRow = r;
    for (const [sev, count] of Object.entries(severityDist)) {
      ws2.getCell(`B${r}`).value = sev;
      ws2.getCell(`C${r}`).value = count;
      ws2.getCell(`D${r}`).value = `${((count / totalSev) * 100).toFixed(1)}%`;
      const label = sev.toUpperCase();
      ws2.getCell(`B${r}`).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: this.severityFillArgb(label) },
      };
      ws2.getCell(`B${r}`).font = {
        bold: true,
        color: { argb: this.severityFontArgb(label) },
      };
      r++;
    }
    this.applyZebraAndBorders(ws2, sevFirstRow, r - 1);

    // ────── EVENTS SHEET ──────
    const ws1 = wb.addWorksheet('Events', {
      views: [{ state: 'frozen', ySplit: 1, showGridLines: false }],
    });
    ws1.columns = [
      { header: 'Timestamp', key: 'collected_at', width: 20 },
      { header: 'Source IP', key: 'source_ip', width: 16 },
      { header: 'Destination IP', key: 'destination_ip', width: 16 },
      { header: 'Username', key: 'user_principal', width: 18 },
      { header: 'Event Type', key: 'event_taxonomy', width: 22 },
      { header: 'Severity', key: 'severity_label', width: 12 },
      { header: 'Machine', key: 'hostname', width: 18 },
      { header: 'Action', key: 'action', width: 16 },
      { header: 'Outcome', key: 'outcome', width: 12 },
      { header: 'Hash ID', key: 'ingestion_hash', width: 20 },
    ];
    this.styleHeaderRow(ws1, 1);

    const logs = data.logs.slice(0, 100000);
    for (const log of logs) {
      const label = this.severityLabel(Number(log.severity));
      const row = ws1.addRow({
        collected_at: fmtDate(log.collected_at),
        source_ip: log.source_ip,
        destination_ip: log.destination_ip ?? '',
        user_principal: log.user_principal ?? '',
        event_taxonomy: log.event_taxonomy,
        severity_label: label,
        hostname: log.hostname,
        action: log.action,
        outcome: log.outcome ?? '',
        ingestion_hash: (log.ingestion_hash ?? '').slice(0, 16),
      });
      const sevCell = row.getCell('severity_label');
      sevCell.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: this.severityFillArgb(label) },
      };
      sevCell.font = {
        bold: true,
        color: { argb: this.severityFontArgb(label) },
      };
      sevCell.alignment = { horizontal: 'center' };
    }
    if (logs.length > 0) {
      this.applyZebraAndBorders(ws1, 2, logs.length + 1);
      ws1.autoFilter = {
        from: { row: 1, column: 1 },
        to: { row: logs.length + 1, column: ws1.columns.length },
      };
    }

    try {
      await wb.xlsx.writeFile(filePath);
    } catch (err) {
      try {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch {
        /* best-effort cleanup */
      }
      throw new Error(
        `Excel generation failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
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
      `[Excel] Generated: ${filename} (${(stat.size / 1024).toFixed(1)} KB)`,
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
          fmtDate(log.collected_at),
          log.source_ip,
          log.destination_ip ?? '',
          log.user_principal ?? '',
          log.event_taxonomy,
          this.severityLabel(Number(log.severity)),
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
      `[CSV] Generated: ${filename} (${(stat.size / 1024).toFixed(1)} KB)`,
    );
    return meta;
  }

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
    const dirs = ['pdf', 'xlsx', 'csv', 'latex'];
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
