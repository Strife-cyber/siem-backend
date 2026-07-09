
import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import type Mail from 'nodemailer/lib/mailer';
import * as handlebars from 'handlebars';
import * as fs from 'node:fs';
import * as path from 'node:path';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly transporter: Mail | null = null;
  private readonly from: string;
  private readonly templates: Map<string, HandlebarsTemplateDelegate> =
    new Map();

  constructor() {
    const host = process.env.SMTP_HOST || 'smtp.gmail.com';
    const port = Number(process.env.SMTP_PORT) || 587;
    const user = process.env.SMTP_USER || '';
    const pass = process.env.SMTP_PASS || '';
    const fromName = process.env.SMTP_FROM_NAME || 'Smart SIEM CTU';
    this.from = process.env.SMTP_FROM || `"${fromName}" <${user}>`;

    if (!user || !pass) {
      this.logger.warn(
        '[Mail] SMTP not configured — emails will be logged only',
      );
      return;
    }

    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
    });

    // Verify connection
    this.transporter
      .verify()
      .then(() => {
        this.logger.log(`[Mail] Connected to ${host}:${port} as ${user}`);
      })
      .catch((err) => {
        this.logger.error(`[Mail] Failed to connect to SMTP: ${err.message}`);
      });

    // Preload templates
    this.loadTemplate('mfa-email', 'mfa-email.hbs');
    this.loadTemplate('incident-alert', 'incident-alert.hbs');
    this.loadTemplate('daily-digest', 'daily-digest.hbs');
  }

  private loadTemplate(name: string, filename: string): void {
    try {
      const templatePath = path.join(process.cwd(), 'templates', filename);
      if (fs.existsSync(templatePath)) {
        const source = fs.readFileSync(templatePath, 'utf-8');
        this.templates.set(name, handlebars.compile(source));
        this.logger.log(`[Mail] Loaded template: ${filename}`);
      } else {
        this.logger.warn(`[Mail] Template not found: ${filename}`);
      }
    } catch (err: any) {
      this.logger.warn(
        `[Mail] Failed to load template ${filename}: ${err.message}`,
      );
    }
  }

  async sendEmail(options: {
    to: string | string[];
    subject: string;
    html: string;
    text?: string;
  }): Promise<boolean> {
    if (!this.transporter) {
      this.logger.log(
        `[Mail] [DRY-RUN] To: ${options.to} | Subject: ${options.subject}`,
      );
      return true;
    }

    try {
      await this.transporter.sendMail({
        from: this.from,
        to: Array.isArray(options.to) ? options.to.join(', ') : options.to,
        subject: options.subject,
        html: options.html,
        text: options.text,
      });
      this.logger.log(`[Mail] Sent to ${options.to}: "${options.subject}"`);
      return true;
    } catch (err: any) {
      this.logger.error(
        `[Mail] Failed to send to ${options.to}: ${err.message}`,
      );
      return false;
    }
  }

  async sendEmailWithAttachment(options: {
    to: string | string[];
    subject: string;
    html: string;
    text?: string;
    attachment: { filename: string; content?: Buffer; path?: string };
  }): Promise<boolean> {
    if (!this.transporter) {
      this.logger.log(
        `[Mail] [DRY-RUN] To: ${options.to} | Subject: ${options.subject} | Attachment: ${options.attachment.filename}`,
      );
      return true;
    }

    try {
      await this.transporter.sendMail({
        from: this.from,
        to: Array.isArray(options.to) ? options.to.join(', ') : options.to,
        subject: options.subject,
        html: options.html,
        attachments: [
          {
            filename: options.attachment.filename,
            content: options.attachment.content,
          },
        ],
      });
      this.logger.log(
        `[Mail] Sent to ${options.to}: "${options.subject}" (attachment: ${options.attachment.filename})`,
      );
      return true;
    } catch (err: any) {
      this.logger.error(
        `[Mail] Failed to send to ${options.to}: ${err.message}`,
      );
      return false;
    }
  }

  async sendMfaCode(
    email: string,
    code: string,
    username: string,
  ): Promise<boolean> {
    const template = this.templates.get('mfa-email');
    const html = template
      ? template({ code, username, expiresIn: 5 })
      : `<h2>Your SIEM Login Code</h2><p style="font-size:32px;letter-spacing:8px;font-weight:bold;">${code}</p><p>Expires in 5 minutes.</p>`;

    return this.sendEmail({
      to: email,
      subject: `[SIEM] Your login verification code: ${code}`,
      html,
    });
  }

  async sendIncidentAlert(incident: {
    id: string;
    severity: string;
    rule_id: string | null;
    rule_name?: string;
    summary: string | null;
    confidence_score: number;
    triggered_at: Date;
    ips?: string[];
    hosts?: string[];
    users?: string[];
  }): Promise<boolean> {
    const colorMap: Record<string, string> = {
      CRITICAL: '#dc2626',
      HIGH: '#ea580c',
      WARNING: '#ca8a04',
      INFO: '#2563eb',
    };
    const color = colorMap[incident.severity] ?? '#6b7280';
    const dashboardUrl =
      process.env.SIEM_DASHBOARD_URL || 'http://localhost:5173';

    // Format time nicely
    const timeStr = incident.triggered_at.toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short',
    });

    // Attacker info for subject line
    const attackerIp = incident.ips?.[0] ?? '';
    const targetHosts = incident.hosts?.join(', ') ?? '';

    const template = this.templates.get('incident-alert');
    const html = template
      ? template({
          ...incident,
          color,
          time_str: timeStr,
          dashboard_url: dashboardUrl,
          join: (arr: string[], sep: string) => arr.join(sep),
        })
      : `<h2 style="color:${color};">[${incident.severity}] ${incident.rule_name || 'Alert'}</h2><p>${incident.summary}</p>`;

    const recipients = (process.env.ALERT_EMAIL_TO || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (recipients.length === 0) {
      this.logger.log(
        '[Mail] No ALERT_EMAIL_TO configured — skipping incident alert',
      );
      return false;
    }

    // Build subject: include attacker IP and target if available
    let subject = `[SIEM] ${incident.severity}`;
    if (attackerIp) subject += ` from ${attackerIp}`;
    if (targetHosts) subject += ` → ${targetHosts}`;
    subject += ` — ${incident.summary?.slice(0, 60) || 'Security Alert'}`;

    return this.sendEmail({
      to: recipients,
      subject: subject.slice(0, 120),
      html,
    });
  }

  async sendDailyDigest(data: {
    date: string;
    total: number;
    counts: Record<string, number>;
    topRules: Array<{ name: string; count: number }>;
  }): Promise<boolean> {
    const template = this.templates.get('daily-digest');
    const html = template
      ? template(data)
      : `<h2>Daily SOC Report — ${data.date}</h2><p>Total incidents: ${data.total}</p>`;

    const recipients = (process.env.ALERT_EMAIL_TO || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (recipients.length === 0) return false;

    return this.sendEmail({
      to: recipients,
      subject: `[SIEM] Daily SOC Report — ${data.date}`,
      html,
    });
  }
}
