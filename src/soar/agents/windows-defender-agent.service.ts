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
//  WindowsDefenderAgentClientService
//
//  Client HTTP vers l'agent Python « ctu-soar-firewall » qui
//  contrôle Windows Defender Firewall via netsh advfirewall.
//
//  Cet agent tourne SUR la machine Windows cible et expose une
//  API REST. Le backend NestJS l'appelle — il n'exécute jamais
//  netsh directement.
//
//  Endpoints du spec :
//    POST /firewall/block       → blockIp
//    POST /firewall/block-port  → blockPort
//    POST /firewall/isolate     → isolateHost
//    GET  /check-ip/{ip}        → checkIp
//    POST /firewall/unblock     → unblockIp
//    GET  /firewall/rules       → listRules
//    DELETE /rule/{name}        → deleteRule
//    GET  /health               → healthCheck
// ============================================================

@Injectable()
export class WindowsDefenderAgentClientService implements IFirewallAgent {
  private readonly logger = new Logger(WindowsDefenderAgentClientService.name);
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;

  readonly provider = 'windows_defender';

  constructor() {
    this.baseUrl =
      process.env.WD_AGENT_URL?.replace(/\/+$/, '') ?? 'http://localhost:8100';
    this.apiKey = process.env.WD_AGENT_API_KEY ?? '';
    this.timeout = Number(process.env.WD_AGENT_TIMEOUT ?? '10000');
  }

  get isConfigured(): boolean {
    return !!this.apiKey;
  }

  // ══════════════════════════════════════════════════
  //  blockIp
  // ══════════════════════════════════════════════════

  async blockIp(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const validation = validateBlockIp(ip);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    return this.post<FirewallActionResponse>('/firewall/block', {
      ip,
      reason: reason ?? 'Blocked by Smart SIEM',
      incident_id: audit?.incident_id,
      playbook_name: audit?.playbook_name,
      attack_type: audit?.attack_type,
      severity: audit?.severity,
      mode: audit?.mode,
    });
  }

  // ══════════════════════════════════════════════════
  //  blockPort
  // ══════════════════════════════════════════════════

  async blockPort(
    ip: string,
    port: number,
    protocol: 'tcp' | 'udp',
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const validation = validateBlockIp(ip);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    return this.post<FirewallActionResponse>('/firewall/block-port', {
      ip,
      port,
      protocol,
      reason: reason ?? 'Port blocked by Smart SIEM',
      incident_id: audit?.incident_id,
      playbook_name: audit?.playbook_name,
    });
  }

  // ══════════════════════════════════════════════════
  //  isolateHost
  // ══════════════════════════════════════════════════

  async isolateHost(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const validation = validateBlockIp(ip);
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    return this.post<FirewallActionResponse>('/firewall/isolate', {
      ip,
      reason: reason ?? 'Isolated by Smart SIEM',
      incident_id: audit?.incident_id,
      playbook_name: audit?.playbook_name,
    });
  }

  // ══════════════════════════════════════════════════
  //  checkIp
  // ══════════════════════════════════════════════════

  async checkIp(ip: string): Promise<CheckIpResponse> {
    return this.get<CheckIpResponse>(`/check-ip/${encodeURIComponent(ip)}`);
  }

  // ══════════════════════════════════════════════════
  //  unblockIp
  // ══════════════════════════════════════════════════

  async unblockIp(ip: string): Promise<FirewallActionResponse> {
    return this.post<FirewallActionResponse>('/firewall/unblock', { ip });
  }

  // ══════════════════════════════════════════════════
  //  listRules
  // ══════════════════════════════════════════════════

  async listRules(): Promise<FirewallActionResponse> {
    return this.get<FirewallActionResponse>('/firewall/rules');
  }

  // ══════════════════════════════════════════════════
  //  deleteRule
  // ══════════════════════════════════════════════════

  async deleteRule(name: string): Promise<FirewallActionResponse> {
    return this.del<FirewallActionResponse>(
      `/rule/${encodeURIComponent(name)}`,
    );
  }

  // ══════════════════════════════════════════════════
  //  healthCheck
  // ══════════════════════════════════════════════════

  async healthCheck(): Promise<FirewallHealth> {
    const result: FirewallHealth = {
      provider: this.provider,
      configured: this.isConfigured,
      reachable: false,
    };

    if (!this.isConfigured) return result;

    try {
      const response = await this.rawGet<Record<string, unknown>>('/health');
      result.reachable = true;
      result.version = String(response.version);
    } catch (err: any) {
      result.error = err.message;
    }

    return result;
  }

  // ══════════════════════════════════════════════════
  //  HTTP primitives
  // ══════════════════════════════════════════════════

  private async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  private async del<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }

  private async rawGet<T>(path: string): Promise<T> {
    // Same as get but without response wrapper parsing (for /health)
    return this.requestInternal<T>('GET', path);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const data = await this.requestInternal<T>(method, path, body);
    // The Python agent wraps responses in { data: ... } for success cases
    return (data as any)?.data ?? data;
  }

  private async requestInternal<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    if (!this.apiKey) {
      const msg = `Windows Defender Agent not configured: WD_AGENT_API_KEY is missing`;
      this.logger.warn(msg);
      throw new Error(msg);
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
      let data: T;
      try {
        data = JSON.parse(text) as T;
      } catch {
        throw new Error(
          `Invalid JSON from Windows Defender Agent: ${text.slice(0, 200)}`,
        );
      }

      if (!response.ok) {
        const errMsg =
          (data as any)?.message ??
          (data as any)?.error ??
          `HTTP ${response.status}`;
        throw new Error(
          `Windows Defender Agent error (${response.status}): ${errMsg}`,
        );
      }

      return data;
    } catch (err: any) {
      if (err.name === 'AbortError') {
        this.logger.error(
          `[WD Agent] Timeout: ${method} ${path} after ${this.timeout}ms`,
        );
        throw new Error(
          `Windows Defender Agent request timed out after ${this.timeout}ms`,
        );
      }
      // Re-throw if it's already our error (with message)
      if (
        err.message?.startsWith('Windows Defender Agent error') ||
        err.message?.startsWith('Invalid JSON')
      ) {
        throw err;
      }
      this.logger.error(`[WD Agent] ${method} ${path}: ${err.message}`);
      throw new Error(`Windows Defender Agent request failed: ${err.message}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
