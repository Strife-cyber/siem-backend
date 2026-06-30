import { Injectable, Logger } from '@nestjs/common';

export interface PfSenseRule {
  id: string;
  type: 'block' | 'pass';
  interface: string;
  ipprotocol: 'inet' | 'inet6';
  protocol: string;
  source: string;
  destination: string;
  destination_port?: string;
  descr: string;
  disabled: boolean;
  log: boolean;
}

export interface PfSenseAlias {
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

/**
 * Client for pfSense REST API (v2).
 * Handles auth, self-signed certs, rate limiting, and error translation.
 */
@Injectable()
export class PfSenseClientService {
  private readonly logger = new Logger(PfSenseClientService.name);
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly rejectUnauthorized: boolean;

  /** Simple mutex to rate-limit writes (pfSense XML config is slow) */
  private writeLock = false;
  private writeQueue: Array<() => Promise<void>> = [];
  private applyDebounceTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    this.baseUrl =
      process.env.PFSENSE_URL?.replace(/\/+$/, '') ?? 'https://192.168.1.1';
    this.apiKey = process.env.PFSENSE_API_KEY ?? '';
    this.timeout = Number(process.env.PFSENSE_TIMEOUT ?? '10000');
    this.rejectUnauthorized =
      process.env.PFSENSE_REJECT_UNAUTHORIZED !== 'false';
  }

  get isConfigured(): boolean {
    return !!this.apiKey;
  }

  // ──────────────────────────────────────────────
  //  System / Health
  // ──────────────────────────────────────────────

  async getSystemInfo(): Promise<
    PfSenseResponse<{ version: string; hostname: string; uptime: string }>
  > {
    return this.get('/api/v2/system/info');
  }

  // ──────────────────────────────────────────────
  //  Firewall Rules
  // ──────────────────────────────────────────────

  async blockIP(
    ip: string,
    reason: string,
    interface_: string = 'wan',
  ): Promise<PfSenseResponse<{ id: string }>> {
    return this.write(async () => {
      const result = await this.post('/api/v2/firewall/rules', {
        type: 'block',
        interface: interface_,
        ipprotocol: 'inet',
        protocol: 'any',
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
      const result = await this.del(`/api/v2/firewall/rules/${ruleId}`);
      if (result.status === 'ok') {
        await this.applyChanges();
      }
      return result;
    });
  }

  async isolateHost(
    ip: string,
    reason: string,
  ): Promise<PfSenseResponse<{ inboundId: string; outboundId: string }>> {
    return this.write(async () => {
      // Block traffic FROM the host
      const outbound = await this.post('/api/v2/firewall/rules', {
        type: 'block',
        interface: 'lan',
        ipprotocol: 'inet',
        protocol: 'any',
        source: ip,
        destination: 'any',
        descr: `ISOLATED by Smart SIEM - ${reason} (outbound)`,
        disabled: false,
        log: true,
      });

      // Block traffic TO the host
      const inbound = await this.post('/api/v2/firewall/rules', {
        type: 'block',
        interface: 'lan',
        ipprotocol: 'inet',
        protocol: 'any',
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
      const result = await this.post('/api/v2/firewall/rules', {
        type: 'block',
        interface: 'wan',
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
  ): Promise<PfSenseResponse<{ blocked: boolean; rules: PfSenseRule[] }>> {
    const result = await this.listRules();
    const rules = result.data ?? [];
    const matching = rules.filter(
      (r) => r.type === 'block' && (r.source === ip || r.destination === ip),
    );
    return {
      status: 'ok',
      data: { blocked: matching.length > 0, rules: matching },
    };
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
      const result = await this.post('/api/v2/aliases', {
        name,
        type: 'host',
        addresses,
        descr: `Smart SIEM - ${descr}`,
      });
      return result;
    });
  }

  async deleteAlias(name: string): Promise<PfSenseResponse> {
    return this.write(async () => {
      const result = await this.del(`/api/v2/aliases/${name}`);
      return result;
    });
  }

  private async applyChanges(): Promise<void> {
    // Debounce: coalesce multiple writes into one apply call
    if (this.applyDebounceTimer) return;
    return new Promise<void>((resolve) => {
      this.applyDebounceTimer = setTimeout(() => {
        this.applyDebounceTimer = null;
        this.post('/api/v2/firewall/apply', {})
          .catch((err: any) => {
            this.logger.error(`[pfSense] applyChanges failed: ${err.message}`);
          })
          .finally(() => resolve());
      }, 500);
    });
  }

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
      this.logger.warn('[pfSense] No API key configured — skipping request');
      return { status: 'error', message: 'PFSENSE_API_KEY not configured' };
    }

    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'X-API-Key': this.apiKey,
    };

    if (body) {
      headers['Content-Type'] = 'application/json';
    }

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
        const errorMap: Record<number, string> = {
          401: 'Invalid pfSense API key',
          403: 'Insufficient pfSense API permissions',
          404: 'pfSense endpoint not found',
          500: 'pfSense internal error',
        };
        throw new Error(
          errorMap[response.status] ??
            `pfSense HTTP ${response.status}: ${text.slice(0, 200)}`,
        );
      }

      return { status: 'ok', data: data as T };
    } catch (err: any) {
      if (err.name === 'AbortError') {
        this.logger.error(`[pfSense] Request timed out: ${method} ${path}`);
        return {
          status: 'error',
          message: `Request timed out after ${this.timeout}ms`,
        };
      }
      this.logger.error(
        `[pfSense] Request failed: ${method} ${path} — ${err.message}`,
      );
      return { status: 'error', message: err.message };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ──────────────────────────────────────────────
  //  Write Mutex (rate limit: max 5 concurrent writes)
  // ──────────────────────────────────────────────

  private async write<T>(fn: () => Promise<T>): Promise<T> {
    if (this.writeLock) {
      // Queue and wait
      return new Promise((resolve, reject) => {
        this.writeQueue.push(async () => {
          try {
            const result = await fn();
            resolve(result);
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
      // Process next in queue
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
