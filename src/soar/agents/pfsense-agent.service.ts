import { Injectable, Logger } from '@nestjs/common';
import type {
  IFirewallAgent,
  FirewallActionResponse,
  FirewallAuditMeta,
  CheckIpResponse,
  FirewallHealth,
} from './firewall-agent.interface';
import { validateBlockIp } from './ip-validation.util';

// ============================================================
//  PfSenseAgentService
//
//  Implémente IFirewallAgent pour le firewall réseau pfSense
//  via son API REST (/api/v2/firewall/rule).
//
//  Conserve les fonctionnalités pfSense-specific (alias) comme
//  méthodes supplémentaires non présentes dans l'interface.
// ============================================================

// ───── Types internes (pfSense-specific) ─────

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
  detail?: string[];
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
export class PfSenseAgentService implements IFirewallAgent {
  private readonly logger = new Logger(PfSenseAgentService.name);
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;

  readonly provider = 'pfsense';

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

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — blockIp (uses Smart_Siem_Blocklist alias)
  // ══════════════════════════════════════════════════

  /** Alias names on pfSense */
  private readonly BLOCKLIST_ALIAS = 'Smart_Siem_Blocklist';
  private readonly ISOLATION_ALIAS = 'Smart_Siem_Isolation';

  async blockIp(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const validation = validateBlockIp(ip);
    if (!validation.valid) throw new Error(validation.error);
    const effectiveReason = reason ?? 'Blocked by Smart SIEM';

    return this.write(async () => {
      await this.addIpToAlias(this.BLOCKLIST_ALIAS, ip, effectiveReason);
      return this.buildResponse(true, {
        action_requested: 'block_ip',
        action_applied: 'block_ip',
        scope: 'network_gateway_inbound',
        effect: `IP ${ip} added to ${this.BLOCKLIST_ALIAS}. Traffic blocked at WAN.`,
        limitations: ['Block applies at network gateway level via alias.'],
        audit: { ...(audit ?? {}) },
        ip,
        reason: effectiveReason,
      });
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — unblockIp (removes from Smart_Siem_Blocklist alias)
  // ══════════════════════════════════════════════════

  async unblockIp(
    ip: string,
    reason?: string,
  ): Promise<FirewallActionResponse> {
    const effectiveReason = reason ?? 'Unblocked by Smart SIEM';
    return this.write(async () => {
      await this.removeIpFromAlias(this.BLOCKLIST_ALIAS, ip);
      return this.buildResponse(true, {
        action_requested: 'unblock_ip',
        action_applied: 'unblock_ip',
        scope: 'network_gateway_inbound',
        effect: `IP ${ip} removed from ${this.BLOCKLIST_ALIAS}. Traffic allowed.`,
        limitations: [],
        ip,
        reason: effectiveReason,
      });
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — isolateHost (adds to Smart_Siem_Isolation alias)
  // ══════════════════════════════════════════════════

  async isolateHost(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const effectiveReason = reason ?? 'Isolated by Smart SIEM';
    return this.write(async () => {
      await this.addIpToAlias(this.ISOLATION_ALIAS, ip, effectiveReason);
      return this.buildResponse(true, {
        action_requested: 'isolate_host',
        action_applied: 'isolate_host',
        scope: 'lan_host_isolation',
        effect: `Host ${ip} added to ${this.ISOLATION_ALIAS}. LAN traffic blocked.`,
        limitations: ['Isolation applies at LAN level via alias.'],
        audit: { ...(audit ?? {}) },
        ip,
        reason: effectiveReason,
      });
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — unIsolateHost
  // ══════════════════════════════════════════════════

  async unIsolateHost(
    ip: string,
    reason?: string,
  ): Promise<FirewallActionResponse> {
    const effectiveReason = reason ?? 'Removed from isolation by Smart SIEM';
    return this.write(async () => {
      await this.removeIpFromAlias(this.ISOLATION_ALIAS, ip);
      return this.buildResponse(true, {
        action_requested: 'unisolate_host',
        action_applied: 'unisolate_host',
        scope: 'lan_host_isolation',
        effect: `Host ${ip} removed from ${this.ISOLATION_ALIAS}. LAN traffic allowed.`,
        limitations: [],
        ip,
        reason: effectiveReason,
      });
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — blockPort
  // ══════════════════════════════════════════════════

  async blockPort(
    ip: string,
    port: number,
    protocol: 'tcp' | 'udp',
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const validation = validateBlockIp(ip);
    if (!validation.valid) throw new Error(validation.error);

    const ruleName = `SmartSIEM-BlockPort-${ip}-${port}-${protocol}`;
    const effectiveReason = reason ?? 'Port blocked by Smart SIEM';

    return this.write(async () => {
      const result = await this.post('/api/v2/firewall/rule', {
        type: 'block',
        interface: ['wan'],
        ipprotocol: 'inet',
        protocol,
        source: ip,
        destination: 'any',
        destination_port: String(port),
        descr: `${ruleName} - ${effectiveReason}`,
        disabled: false,
        log: true,
      });

      if (result.status === 'ok') {
        await this.applyChanges();
      }

      return this.buildResponse(result.status === 'ok', {
        action_requested: 'block_port',
        action_applied: result.status === 'ok' ? 'block_port' : 'none',
        scope: 'network_gateway_inbound',
        effect: `Traffic from ${ip} on ${protocol}/${port} blocked at gateway.`,
        limitations: [
          'Block applies at network gateway level.',
          `Only ${protocol} port ${port} is blocked; other traffic from ${ip} is unaffected.`,
        ],
        audit: { ...(audit ?? {}) },
        ip,
        port,
        protocol,
        rule_name: ruleName,
        reason: effectiveReason,
        pfSenseRuleId: (result.data as any)?.id,
      });
    });
  }



  // ══════════════════════════════════════════════════
  //  IFirewallAgent — checkIp
  // ══════════════════════════════════════════════════

  async checkIp(ip: string): Promise<CheckIpResponse> {
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

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — listRules
  // ══════════════════════════════════════════════════

  async listRules(): Promise<FirewallActionResponse> {
    const result = await this.get<PfSenseRule[]>('/api/v2/firewall/rules');
    const rules = result.data ?? [];

    return this.buildResponse(true, {
      action_requested: 'list_rules',
      action_applied: 'list_rules',
      scope: 'network_gateway',
      effect: `Retrieved ${rules.length} firewall rules.`,
      limitations: [
        'All pfSense rules are listed, not only Smart SIEM-managed ones.',
      ],
      rules,
      count: rules.length,
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — deleteRule
  // ══════════════════════════════════════════════════

  async deleteRule(name: string): Promise<FirewallActionResponse> {
    return this.write(async () => {
      const rulesResult = await this.get<PfSenseRule[]>(
        '/api/v2/firewall/rules',
      );
      const allRules = rulesResult.data ?? [];

      // Find rules whose description matches the given name
      const matching = allRules.filter((r) => r.descr?.startsWith(name));

      let deletedCount = 0;
      for (const rule of matching) {
        const delResult = await this.del(
          `/api/v2/firewall/rule?id=${encodeURIComponent(rule.id)}`,
        );
        if (delResult.status === 'ok') deletedCount++;
      }

      if (deletedCount > 0) {
        await this.applyChanges();
      }

      return this.buildResponse(true, {
        action_requested: 'delete_rule',
        action_applied: 'delete_rule',
        scope: 'network_gateway',
        effect:
          deletedCount > 0
            ? `Deleted ${deletedCount} rule(s) matching "${name}".`
            : `No rules found matching "${name}".`,
        limitations: [
          'Only rules created by Smart SIEM are affected.',
          'Deletion is idempotent — no error if no rule matches.',
        ],
        rule_name: name,
        deleted_count: deletedCount,
      });
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — healthCheck
  // ══════════════════════════════════════════════════

  async healthCheck(): Promise<FirewallHealth> {
    const result: FirewallHealth = {
      provider: this.provider,
      configured: this.isConfigured,
      reachable: false,
    };

    if (!this.isConfigured) return result;

    try {
      const info = await this.get('/api/v2/system/info');
      if (info.status === 'ok') {
        const d = info.data as any;
        result.reachable = true;
        result.version = d?.version ?? d?.data?.version;
      }
    } catch (err: any) {
      result.error = err.message;
    }

    return result;
  }

  // ══════════════════════════════════════════════════
  //  Méthodes pfSense-specific (hors IFirewallAgent)
  // ══════════════════════════════════════════════════

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
      const rules = await this.get('/api/v2/firewall/rules');
      if (rules.status === 'ok') {
        result.rulesCount = ((rules.data as any[]) ?? []).length;
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

  async blockIP_deprecated(
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

  async unblockIP_deprecated(ruleId: string): Promise<PfSenseResponse> {
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
    const result = await this.get<any>('/api/v2/firewall/aliases');
    // pfSense API wraps the array in a nested data field
    if (result.status === 'ok' && result.data && Array.isArray(result.data.data)) {
      return { status: 'ok', data: result.data.data as PfSenseAlias[] };
    }
    if (result.status === 'ok' && Array.isArray(result.data)) {
      return { status: 'ok', data: result.data as PfSenseAlias[] };
    }
    return { status: 'error', data: [], message: 'Unexpected alias list format' };
  }

  // ══════════════════════════════════════════════════
  //  Alias helpers
  // ══════════════════════════════════════════════════

  /**
   * Add an IP address to a pfSense alias.
   * Fetches current alias, appends IP, PATCHes back, applies changes.
   */
  private async addIpToAlias(
    aliasName: string,
    ip: string,
    reason: string,
  ): Promise<void> {
    const allResult = await this.listAliases();
    const alias = (allResult.data ?? []).find((a: PfSenseAlias) => a.name === aliasName);

    if (alias) {
      const currentAddresses: string[] = alias.addresses ?? [];
      if (currentAddresses.includes(ip)) {
        this.logger.log(`[pfSense] IP ${ip} already in alias "${aliasName}"`);
        return;
      }
      // Delete existing alias (pfSense API doesn't support update)
      await this.del(`/api/v2/firewall/alias?id=${encodeURIComponent(alias.id)}`).catch(() => {});
    }

    // Build final list: existing IPs (minus deleted) + new IP
    const existingAddresses = alias?.addresses ?? [];
    const existingDetails = alias?.detail ?? [];
    const filteredAddresses = existingAddresses.filter((a) => a !== ip);
    const addresses = [...filteredAddresses, ip];
    // Keep matching detail entries, add new reason for new IP
    const detail = [
      ...existingDetails.slice(0, filteredAddresses.length),
      reason,
    ];

    const createResult = await this.post('/api/v2/firewall/alias', {
      name: aliasName,
      type: 'host',
      address: addresses,
      detail,
      descr: alias?.descr ?? `Smart SIEM - ${aliasName}`,
    });

    if (createResult.status !== 'ok') {
      this.logger.error(`[pfSense] Failed to create alias "${aliasName}": ${createResult.message}`);
      throw new Error(`Failed to update alias "${aliasName}": ${createResult.message}`);
    }

    await this.applyChanges();
    this.logger.log(
      `[pfSense] Added ${ip} to alias "${aliasName}" (${addresses.length} total)`,
    );
  }

  private async removeIpFromAlias(
    aliasName: string,
    ip: string,
  ): Promise<void> {
    const allResult = await this.listAliases();
    const alias = (allResult.data ?? []).find((a: PfSenseAlias) => a.name === aliasName);
    if (!alias) {
      this.logger.log(`[pfSense] Alias "${aliasName}" not found, nothing to remove`);
      return;
    }
    const currentAddresses: string[] = alias.addresses ?? [];

    if (!currentAddresses.includes(ip)) {
      this.logger.log(`[pfSense] IP ${ip} not in alias "${aliasName}"`);
      return;
    }

    const addresses = currentAddresses.filter((a) => a !== ip);

    // Delete and recreate
    await this.del(`/api/v2/firewall/alias?id=${encodeURIComponent(alias.id)}`).catch(() => {});

    const createResult = await this.post('/api/v2/firewall/alias', {
      name: aliasName,
      type: 'host',
      address: addresses,
      detail: addresses.map(() => 'Smart SIEM'),
      descr: alias.descr ?? '',
    });

    if (createResult.status !== 'ok') {
      throw new Error(
        `Failed to recreate alias "${aliasName}": ${createResult.message}`,
      );
    }

    await this.applyChanges();
    this.logger.log(
      `[pfSense] Removed ${ip} from alias "${aliasName}" (${addresses.length} total)`,
    );
  }

  // ══════════════════════════════════════════════════
  //  Internes
  // ══════════════════════════════════════════════════

  private buildResponse(
    success: boolean,
    fields: Partial<FirewallActionResponse> & {
      action_requested: string;
      action_applied: string;
      scope: string;
      effect: string;
    },
  ): FirewallActionResponse {
    return {
      provider: this.provider,
      ...fields,
      limitations: fields.limitations ?? [],
      audit: fields.audit ?? {},
      success,
    };
  }

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
