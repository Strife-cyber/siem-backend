import { Injectable, Logger } from '@nestjs/common';

export interface PfSenseRule {
  id: string;
  type: 'block' | 'pass';
  interface: string[];
  ipprotocol: 'inet' | 'inet6';
  source: string;
  destination: string;
  destination_port?: string;
  descr: string;
  disabled: boolean;
  log: boolean;
}

export interface PfSenseAlias {
  id: string;
  name: string;
  type: 'host' | 'network' | 'port';
  addresses: string[];
  descr: string;
}

export interface PfSenseResponse<T = unknown> {
  status: 'ok' | 'error';
  data?: T;
  message?: string;
}

export interface PfSenseStatus {
  configured: boolean;
  baseUrl: string;
  reachable: boolean;
  version?: string;
  hostname?: string;
  uptime?: string;
  rulesCount?: number;
  aliasesCount?: number;
  lastError?: string;
}

@Injectable()
export class PfSenseClientService {
  private readonly logger = new Logger(PfSenseClientService.name);
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;

  private writeLock = false;
  private writeQueue: Array<() => Promise<void>> = [];
  private applyDebounceTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    this.baseUrl =
      process.env.PFSENSE_URL?.replace(/\/+$/, '') ?? 'http://192.168.37.135';
    this.apiKey = process.env.PFSENSE_API_KEY ?? '';
    this.timeout = Number(process.env.PFSENSE_TIMEOUT ?? '10000');
  }

  get isConfigured(): boolean {
    return !!this.apiKey;
  }

  // ──────────────────────────────────────────────
  //  Status / Health
  // ──────────────────────────────────────────────

  async getStatus(): Promise<PfSenseStatus> {
    const result: PfSenseStatus = {
      configured: this.isConfigured,
      baseUrl: this.baseUrl,
      reachable: false,
    };

    if (!this.isConfigured) return result;

    try {
      const info = await this.get('/api/v2/system/info');
      if (info.status === 'ok') {
        const d = info.data as any;
        result.reachable = true;
        result.version = d?.version ?? d?.data?.version;
        result.hostname = d?.hostname ?? d?.data?.hostname;
        result.uptime = d?.uptime ?? d?.data?.uptime;
      }
      const rules = await this.listRules();
      if (rules.status === 'ok') {
        result.rulesCount = (rules.data ?? []).length;
      }
      const aliases = await this.get('/api/v2/firewall/aliases');
      if (aliases.status === 'ok') {
        result.aliasesCount = ((aliases.data as any[]) ?? []).length;
      }
    } catch (err: any) {
      result.lastError = err.message;
    }

    return result;
  }

  // ──────────────────────────────────────────────
  //  Firewall Rules
  // ──────────────────────────────────────────────

  async blockIP(
    ip: string,
    reason: string,
  ): Promise<PfSenseResponse<{ id: string }>> {
    return this.write(async () => {
      const result = await this.post('/api/v2/firewall/rule', {
        type: 'block',
        interface: ['wan'],
        ipprotocol: 'inet',
        source: ip,
        destination: 'any',
        descr: `BLOCKED by Smart SIEM - ${reason}`,
        disabled: false,
        log: true,
      });
      if (result.status === 'ok') {
        await this.applyChanges();
      }
      return result as any;
    });
  }

  async unblockIP(ruleId: string): Promise<PfSenseResponse> {
    return this.write(async () => {
      const result = await this.del(
        `/api/v2/firewall/rule?id=${encodeURIComponent(ruleId)}`,
      );
      if (result.status === 'ok') {
        await this.applyChanges();
      }
      return result;
    });
  }

  async isolateHost(
    ip: string,
    reason: string,
  ): Promise<PfSenseResponse<{ outboundId: string; inboundId: string }>> {
    return this.write(async () => {
      const outbound = await this.post('/api/v2/firewall/rule', {
        type: 'block',
        interface: ['lan'],
        ipprotocol: 'inet',
        source: ip,
        destination: 'any',
        descr: `ISOLATED by Smart SIEM - ${reason} (outbound)`,
        disabled: false,
        log: true,
      });

      const inbound = await this.post('/api/v2/firewall/rule', {
        type: 'block',
        interface: ['lan'],
        ipprotocol: 'inet',
        source: 'any',
        destination: ip,
        descr: `ISOLATED by Smart SIEM - ${reason} (inbound)`,
        disabled: false,
        log: true,
      });

      await this.applyChanges();
      return {
        status: 'ok',
        data: {
          outboundId: (outbound as any)?.data?.id ?? 'unknown',
          inboundId: (inbound as any)?.data?.id ?? 'unknown',
        },
      } as any;
    });
  }

  async blockPort(
    ip: string,
    port: number,
    protocol: 'tcp' | 'udp',
    reason: string,
  ): Promise<PfSenseResponse<{ id: string }>> {
    return this.write(async () => {
      const result = await this.post('/api/v2/firewall/rule', {
        type: 'block',
        interface: ['wan'],
        ipprotocol: 'inet',
        protocol,
        source: ip,
        destination: 'any',
        destination_port: String(port),
        descr: `BLOCKED by Smart SIEM - ${reason} (port ${port})`,
        disabled: false,
        log: true,
      });
      if (result.status === 'ok') {
        await this.applyChanges();
      }
      return result as any;
    });
  }

  async listRules(): Promise<PfSenseResponse<PfSenseRule[]>> {
    return this.get('/api/v2/firewall/rules');
  }

  async checkIP(
    ip: string,
  ): Promise<{ blocked: boolean; rules: PfSenseRule[] }> {
    try {
      const result = await this.listRules();
      const rules = (result.data ?? []) as any[];
      const matching = rules.filter(
        (r: any) =>
          r.type === 'block' && (r.source === ip || r.destination === ip),
      );
      return { blocked: matching.length > 0, rules: matching as PfSenseRule[] };
    } catch {
      return { blocked: false, rules: [] };
    }
  }

  // ──────────────────────────────────────────────
  //  Aliases
  // ──────────────────────────────────────────────

  async createAlias(
    name: string,
    addresses: string[],
    descr: string,
  ): Promise<PfSenseResponse> {
    return this.write(async () => {
      return this.post('/api/v2/firewall/alias', {
        name,
        type: 'host',
        addresses,
        descr: `Smart SIEM - ${descr}`,
      });
    });
  }

  async deleteAlias(id: string): Promise<PfSenseResponse> {
    return this.write(async () => {
      return this.del(`/api/v2/firewall/alias?id=${encodeURIComponent(id)}`);
    });
  }

  async listAliases(): Promise<PfSenseResponse<PfSenseAlias[]>> {
    return this.get('/api/v2/firewall/aliases');
  }

  // ──────────────────────────────────────────────
  //  Apply Changes
  // ──────────────────────────────────────────────

  private async applyChanges(): Promise<void> {
    if (this.applyDebounceTimer) return;
    return new Promise<void>((resolve) => {
      this.applyDebounceTimer = setTimeout(() => {
        this.applyDebounceTimer = null;
        this.post('/api/v2/firewall/apply', {})
          .catch((err: any) =>
            this.logger.error(`[pfSense] applyChanges failed: ${err.message}`),
          )
          .finally(() => resolve());
      }, 500);
    });
  }

  // ──────────────────────────────────────────────
  //  HTTP Methods
  // ──────────────────────────────────────────────

  private async get<T>(path: string): Promise<PfSenseResponse<T>> {
    return this.request('GET', path);
  }

  private async post<T>(
    path: string,
    body?: unknown,
  ): Promise<PfSenseResponse<T>> {
    return this.request('POST', path, body);
  }

  private async del<T>(path: string): Promise<PfSenseResponse<T>> {
    return this.request('DELETE', path);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<PfSenseResponse<T>> {
    if (!this.apiKey) {
      this.logger.warn('[pfSense] No API key configured');
      return { status: 'error', message: 'PFSENSE_API_KEY not configured' };
    }

    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { 'X-API-Key': this.apiKey };
    if (body) headers['Content-Type'] = 'application/json';

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const text = await response.text();
      let data: any;
      try {
        data = JSON.parse(text);
      } catch {
        data = { raw: text };
      }

      if (!response.ok) {
        const map: Record<number, string> = {
          401: 'Invalid pfSense API key',
          403: 'Insufficient permissions',
          404: 'Endpoint not found',
          500: 'pfSense internal error',
        };
        throw new Error(
          map[response.status] ??
            `HTTP ${response.status}: ${text.slice(0, 200)}`,
        );
      }

      return { status: 'ok', data: data as T };
    } catch (err: any) {
      if (err.name === 'AbortError') {
        this.logger.error(`[pfSense] Timeout: ${method} ${path}`);
        return {
          status: 'error',
          message: `Request timed out after ${this.timeout}ms`,
        };
      }
      this.logger.error(`[pfSense] ${method} ${path}: ${err.message}`);
      return { status: 'error', message: err.message };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async write<T>(fn: () => Promise<T>): Promise<T> {
    if (this.writeLock) {
      return new Promise((resolve, reject) => {
        this.writeQueue.push(async () => {
          try {
            resolve(await fn());
          } catch (err) {
            reject(err instanceof Error ? err : new Error(String(err)));
          }
        });
      });
    }
    this.writeLock = true;
    try {
      return await fn();
    } finally {
      this.writeLock = false;
      const next = this.writeQueue.shift();
      if (next) {
        this.writeLock = true;
        void next().finally(() => {
          this.writeLock = false;
        });
      }
    }
  }
}
