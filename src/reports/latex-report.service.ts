import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import * as Handlebars from 'handlebars';

export interface LaTeXReportMeta {
  id: string;
  filename: string;
  size_bytes: number;
  created_at: string;
  expires_at: string;
}

// ────────────────────────────────────────────────────────────────
//  Data the Handlebars template expects
// ────────────────────────────────────────────────────────────────
interface ReportTemplateData {
  period_start: string;
  period_end: string;
  generated_date: string;
  logs_per_hour: number;
  // KPI cards
  active_incidents: number;
  critical_alerts: number;
  high_alerts: number;
  playbooks_executed: number;
  // Severity distribution (%)
  severity_info_pct: string;
  severity_warning_pct: string;
  severity_high_pct: string;
  severity_critical_pct: string;
  // Top IP sources
  top_sources: Array<{ ip: string; count: number }>;
  top_sources_max: number;
  // Threat types
  has_threat_types: boolean;
  threat_types: Array<{ label: string; count: number }>;
  threat_types_max: number;
  // UEBA
  has_ueba: boolean;
  ueba_anomalies: Array<{
    entity: string;
    risk_score: number;
    anomaly_type: string;
    description: string;
  }>;
  // Incidents
  incidents: Array<{
    severity: string;
    rule_id: string;
    summary: string;
  }>;
  // Audit trail
  audit_trails: Array<{
    user_id: string;
    role: string;
    action: string;
  }>;
}

// ────────────────────────────────────────────────────────────────
//  LaTeX special-character escaping
// ────────────────────────────────────────────────────────────────
function escapeLatex(raw: string | number | null | undefined): string {
  if (raw == null) return '-';
  const s = String(raw);
  return s
    .replace(/\\/g, '\\textbackslash{}')
    .replace(/&/g, '\\&')
    .replace(/%/g, '\\%')
    .replace(/\$/g, '\\$')
    .replace(/#/g, '\\#')
    .replace(/_/g, '\\_')
    .replace(/{/g, '\\{')
    .replace(/}/g, '\\}')
    .replace(/~/g, '\\textasciitilde{}')
    .replace(/\^/g, '\\textasciicircum{}');
}

@Injectable()
export class LatexReportService {
  private readonly logger = new Logger(LatexReportService.name);
  private readonly reportsDir: string;
  private readonly latexDir: string;
  private template: HandlebarsTemplateDelegate<ReportTemplateData> | null = null;

  constructor() {
    this.reportsDir =
      process.env.REPORTS_DIR || path.join(process.cwd(), 'reports');
    this.latexDir = path.join(this.reportsDir, 'latex');
    fs.mkdirSync(this.reportsDir, { recursive: true });
    fs.mkdirSync(path.join(this.reportsDir, 'pdf'), { recursive: true });
    fs.mkdirSync(this.latexDir, { recursive: true });

    this.loadTemplate();
  }

  /** Load and compile the Handlebars LaTeX template */
  private loadTemplate(): void {
    try {
      const tmplPath = path.join(process.cwd(), 'templates', 'report.tex.hbs');
      if (!fs.existsSync(tmplPath)) {
        this.logger.warn(
          `[LaTeX] Template not found at ${tmplPath} — PDF generation will fail`,
        );
        return;
      }
      const source = fs.readFileSync(tmplPath, 'utf-8');
      this.template = Handlebars.compile<ReportTemplateData>(source);
      this.logger.log('[LaTeX] Template compiled successfully');
    } catch (err: any) {
      this.logger.error(
        `[LaTeX] Failed to compile template: ${err.message}`,
      );
    }
  }

  /**
   * Generate a PDF report from the provided data by rendering the LaTeX
   * template and compiling with pdflatex.
   */
  async generate(
    data: {
      overview: any;
      incidents: any[];
      auditTrails: any[];
      uebaProfiles: any[];
    },
    request: { start_date: string; end_date: string },
  ): Promise<LaTeXReportMeta> {
    if (!this.template) {
      throw new Error(
        'LaTeX template not loaded. Ensure templates/report.tex.hbs exists.',
      );
    }

    const id = crypto.randomUUID();
    const filename = `${request.start_date.slice(0, 10)}-report-${id.slice(0, 8)}.pdf`;
    const pdfPath = path.join(this.reportsDir, 'pdf', filename);

    // ── 1. Prepare template data ──────────────────────────────
    const { overview, incidents, auditTrails, uebaProfiles } = data;
    const severityDist: Record<string, number> =
      overview?.severity_distribution ?? {};
    const stats = overview?.stats ?? {};
    const topSources: Array<{ source_ip: string; count: number }> =
      overview?.top_sources ?? [];
    const threatTypes: Array<{ type: string; count: number }> =
      overview?.threat_types ?? [];

    const total =
      Object.values(severityDist).reduce((a, b) => a + b, 0) || 1;

    const severityInfoPct = (
      ((severityDist.INFO ?? 0) / total) *
      100
    ).toFixed(0);
    const severityWarningPct = (
      ((severityDist.WARNING ?? 0) / total) *
      100
    ).toFixed(0);
    const severityHighPct = (
      ((severityDist.HIGH ?? 0) / total) *
      100
    ).toFixed(0);
    const severityCriticalPct = (
      ((severityDist.CRITICAL ?? 0) / total) *
      100
    ).toFixed(0);

    // Top IP sources — take 4 max (template layout limit)
    const topSources4 = topSources.slice(0, 4).map((s) => ({
      ip: escapeLatex(s.source_ip),
      count: s.count,
    }));
    const topSourcesMax =
      topSources4.length > 0
        ? Math.max(...topSources4.map((s) => s.count))
        : 1;

    // Threat types — take 4 max
    const threatTypes4 = threatTypes.slice(0, 4).map((t) => ({
      label: escapeLatex(t.type),
      count: t.count,
    }));
    const threatTypesMax =
      threatTypes4.length > 0
        ? Math.max(...threatTypes4.map((t) => t.count))
        : 1;

    // UEBA anomalies
    const uebaAnomalies = (uebaProfiles ?? []).slice(0, 3).map((p: any) => ({
      entity: escapeLatex(p.user_principal ?? 'unknown'),
      risk_score: p.risk_score ?? 0,
      anomaly_type: 'COMPORTEMENT ANORMAL',
      description: escapeLatex(
        p.anomaly_count > 0
          ? `Score de risque: ${p.risk_score}/100. Anomalies détectées: ${p.anomaly_count}. Analyse basée sur les logs récents.`
          : `Score de risque: ${p.risk_score}/100. Comportement dans les limites de la baseline établie.`,
      ),
    }));

    // Incidents — take 25 max
    const incidentRows = (incidents ?? []).slice(0, 25).map((i: any) => ({
      severity: escapeLatex(i.severity ?? 'INFO'),
      rule_id: escapeLatex(i.rule_id ?? '-'),
      summary: escapeLatex(i.summary ?? 'Aucun détail disponible'),
    }));

    // Audit trails — take 20 max
    const auditRows = (auditTrails ?? []).slice(0, 20).map((a: any) => ({
      user_id: escapeLatex(a.user_id ?? '-'),
      role: escapeLatex(
        (a as any).user?.role ?? a.role ?? 'Analyste',
      ),
      action: escapeLatex(a.action ?? '-'),
    }));

    const periodStart = request.start_date.slice(0, 10);
    const periodEnd = request.end_date.slice(0, 10);

    const templateData: ReportTemplateData = {
      period_start: periodStart,
      period_end: periodEnd,
      generated_date: new Date().toISOString().replace('T', ' ').slice(0, 16),
      logs_per_hour: stats.logs_per_hour ?? 0,
      active_incidents: stats.open_incidents ?? 0,
      critical_alerts: severityDist.CRITICAL ?? 0,
      high_alerts: severityDist.HIGH ?? 0,
      playbooks_executed: incidents?.length ?? 0,
      severity_info_pct: severityInfoPct,
      severity_warning_pct: severityWarningPct,
      severity_high_pct: severityHighPct,
      severity_critical_pct: severityCriticalPct,
      top_sources: topSources4,
      top_sources_max: topSourcesMax,
      has_threat_types: threatTypes4.length > 0,
      threat_types: threatTypes4,
      threat_types_max: threatTypesMax,
      has_ueba: uebaAnomalies.length > 0,
      ueba_anomalies: uebaAnomalies,
      incidents: incidentRows,
      audit_trails: auditRows,
    };

    // ── 2. Render and write .tex ──────────────────────────────
    const renderedTex = this.template(templateData);
    const texId = `${request.start_date.slice(0, 10)}-${id.slice(0, 8)}`;
    const texPath = path.join(this.latexDir, `${texId}.tex`);
    fs.writeFileSync(texPath, renderedTex, 'utf-8');

    // ── 3. Compile with pdflatex (two passes) ─────────────────
    try {
      this.runPdflatex(texId);
      this.runPdflatex(texId);
    } catch (err: any) {
      // Try to read the log for a better error message
      const logPath = path.join(this.latexDir, `${texId}.log`);
      let detail = err.message;
      try {
        if (fs.existsSync(logPath)) {
          const logContent = fs.readFileSync(logPath, 'utf-8');
          const errorLines = logContent
            .split('\n')
            .filter(
              (l) =>
                l.includes('! ') &&
                !l.includes('! LaTeX') &&
                !l.includes('! ==>'),
            )
            .slice(0, 3)
            .join('; ');
          if (errorLines) detail = errorLines;
        }
      } catch {
        /* best-effort */
      }
      this.cleanupAuxFiles(texId);
      throw new Error(`LaTeX compilation failed: ${detail}`);
    }

    // ── 4. Move PDF to final destination ──────────────────────
    const compiledPdf = path.join(this.latexDir, `${texId}.pdf`);
    if (!fs.existsSync(compiledPdf)) {
      this.cleanupAuxFiles(texId);
      throw new Error('pdflatex completed but no PDF was produced');
    }
    fs.renameSync(compiledPdf, pdfPath);

    // ── 5. Cleanup temporary files ────────────────────────────
    this.cleanupAuxFiles(texId);

    if (!fs.existsSync(pdfPath)) {
      throw new Error(`PDF file was not created at ${pdfPath}`);
    }

    const stat = fs.statSync(pdfPath);
    if (stat.size < 500) {
      this.logger.warn(
        `[LaTeX] Generated PDF is very small (${stat.size} bytes)`,
      );
    }

    const meta: LaTeXReportMeta = {
      id,
      filename,
      size_bytes: stat.size,
      created_at: new Date().toISOString(),
      expires_at: new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000,
      ).toISOString(),
    };

    this.logger.log(
      `[LaTeX] Generated: ${filename} (${(stat.size / 1024).toFixed(1)} KB)`,
    );
    return meta;
  }

  // ────────────────────────────────────────────────────────────
  //  Internal helpers
  // ────────────────────────────────────────────────────────────

  /** Run pdflatex on the .tex file in latexDir */
  private runPdflatex(texId: string): void {
    const texPath = path.join(this.latexDir, `${texId}.tex`);
    const result = spawnSync('pdflatex', [
      '-interaction=nonstopmode',
      `-output-directory=${this.latexDir}`,
      texPath,
    ], {
      timeout: 60_000,
      maxBuffer: 2 * 1024 * 1024,
      stdio: 'pipe',
    });

    const output = result.stdout?.toString() ?? '';
    // Exit code ≠ 0 or fatal error → fail
    if (result.status !== 0 || /! Emergency stop/.test(output)) {
      const errorMatch = output.match(/! .*/);
      const detail = errorMatch
        ? errorMatch[0]
        : `pdflatex exited with code ${result.status} (see .log for details)`;
      // Append stderr if available
      const stderr = result.stderr?.toString()?.trim();
      const msg = stderr ? `${detail} — ${stderr}` : detail;
      throw new Error(msg);
    }
  }

  /** Remove auxiliary files generated by pdflatex */
  private cleanupAuxFiles(texId: string): void {
    const extensions = ['.tex', '.aux', '.log', '.out', '.toc', '.synctex.gz'];
    for (const ext of extensions) {
      const fp = path.join(this.latexDir, `${texId}${ext}`);
      try {
        if (fs.existsSync(fp)) fs.unlinkSync(fp);
      } catch {
        /* best-effort */
      }
    }
  }
}
