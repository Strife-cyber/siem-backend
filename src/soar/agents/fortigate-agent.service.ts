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
//  FortiGateAgentService
//
//  Implements IFirewallAgent for Fortinet FortiGate via the
//  FortiOS REST API (Bearer token auth):
//    - address objects : /api/v2/cmdb/firewall/address
//    - deny policies   : /api/v2/cmdb/firewall/policy
//    - port services   : /api/v2/cmdb/firewall.service/custom
//
//  Every Smart SIEM object is prefixed SmartSIEM- so listRules /
//  deleteRule / unblocking stay scoped to what this agent manages.
// ============================================================

interface FortiResponse<T = unknown> {
  status?: string;
  http_status?: number;
  http_method?: string;
  revision?: string;
  results?: T;
  error?: unknown;
}

@Injectable()
export class FortiGateAgentService implements IFirewallAgent {
  private readonly logger = new Logger(FortiGateAgentService.name);
  private readonly baseUrl: string;
  private readonly apiToken: string;
  private readonly timeout: number;

  readonly provider = 'fortigate';

  private static readonly PREFIX = 'SmartSIEM';

  constructor() {
    this.baseUrl =
      process.env.FORTIGATE_URL?.replace(/\/+$/, '') ??
      'https://192.168.37.136';
    this.apiToken = process.env.FORTIGATE_API_TOKEN ?? '';
    this.timeout = Number(process.env.FORTIGATE_TIMEOUT ?? '10000');
  }

  get isConfigured(): boolean {
    return !!this.apiToken;
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — blockIp
  // ══════════════════════════════════════════════════

  async blockIp(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const validation = validateBlockIp(ip);
    if (!validation.valid) throw new Error(validation.error);
    const effectiveReason = reason ?? 'Blocked by Smart SIEM';
    const addrName = `SmartSIEM-Block-${ip}`;

    await this.ensureAddressObject(addrName, ip, effectiveReason);
    await this.ensurePolicy(addrName, addrName, 'all', undefined);

    return this.buildResponse(true, {
      action_requested: 'block_ip',
      action_applied: 'block_ip',
      scope: 'network_gateway_inbound',
      effect: `Traffic from IP ${ip} denied at the gateway (address object ${addrName} + policy).`,
      limitations: [
        'Deny policy is appended to the policy list; verify ordering if a broad allow policy exists above it.',
      ],
      audit: { ...(audit ?? {}) },
      ip,
      reason: effectiveReason,
      address_object: addrName,
    });
  }

  async unblockIp(ip: string): Promise<FirewallActionResponse> {
    const addrName = `SmartSIEM-Block-${ip}`;
    const policyOk = await this.deletePolicy(addrName);
    const addrOk = await this.deleteAddressObject(addrName);
    if (!policyOk || !addrOk) {
      throw new Error(
        `FortiGate unblock failed for ${ip}: policy=${policyOk} address=${addrOk}`,
      );
    }
    return this.buildResponse(true, {
      action_requested: 'unblock_ip',
      action_applied: 'unblock_ip',
      scope: 'network_gateway_inbound',
      effect: `IP ${ip} block removed (address object ${addrName} deleted).`,
      limitations: [],
      ip,
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — isolateHost (both directions)
  // ══════════════════════════════════════════════════

  async isolateHost(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const validation = validateBlockIp(ip);
    if (!validation.valid) throw new Error(validation.error);
    const effectiveReason = reason ?? 'Isolated by Smart SIEM';
    const addrName = `SmartSIEM-Isolate-${ip}`;

    await this.ensureAddressObject(addrName, ip, effectiveReason);
    // Host's outbound traffic: source = host object, destination = any
    await this.ensurePolicy(`${addrName}-out`, addrName, 'all', undefined);
    // Inbound traffic to the host: source = any, destination = host object
    await this.ensurePolicy(`${addrName}-in`, 'all', addrName, undefined);

    return this.buildResponse(true, {
      action_requested: 'isolate_host',
      action_applied: 'isolate_host',
      scope: 'lan_host_isolation',
      effect: `Host ${ip} denied both directions (outbound + inbound policies).`,
      limitations: [
        'Isolation is enforced at the gateway; east-west traffic not traversing it is unaffected.',
      ],
      audit: { ...(audit ?? {}) },
      ip,
      reason: effectiveReason,
      address_object: addrName,
    });
  }

  async unIsolateHost(ip: string): Promise<FirewallActionResponse> {
    const addrName = `SmartSIEM-Isolate-${ip}`;
    const outOk = await this.deletePolicy(`${addrName}-out`);
    const inOk = await this.deletePolicy(`${addrName}-in`);
    const addrOk = await this.deleteAddressObject(addrName);
    if (!outOk || !inOk || !addrOk) {
      throw new Error(
        `FortiGate un-isolate failed for ${ip}: out=${outOk} in=${inOk} address=${addrOk}`,
      );
    }
    return this.buildResponse(true, {
      action_requested: 'unisolate_host',
      action_applied: 'unisolate_host',
      scope: 'lan_host_isolation',
      effect: `Host ${ip} isolation removed.`,
      limitations: [],
      ip,
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
    const effectiveReason = reason ?? 'Port blocked by Smart SIEM';
    const addrName = `SmartSIEM-Port-${ip}-${port}`;
    const svcName = `SmartSIEM-Svc-${port}-${protocol}`;

    await this.ensureAddressObject(addrName, ip, effectiveReason);
    await this.ensureServiceObject(svcName, port, protocol, effectiveReason);
    await this.ensurePolicy(addrName, addrName, 'all', svcName);

    return this.buildResponse(true, {
      action_requested: 'block_port',
      action_applied: 'block_port',
      scope: 'network_gateway_inbound',
      effect: `Traffic from ${ip} to ${protocol}/${port} denied at gateway.`,
      limitations: ['Only inbound traffic to the specified port is denied.'],
      audit: { ...(audit ?? {}) },
      ip,
      port,
      protocol,
      address_object: addrName,
      service_object: svcName,
      reason: effectiveReason,
    });
  }

  // ══════════════════════════════════════════════════
  //  IFirewallAgent — checkIp / listRules / deleteRule
  // ══════════════════════════════════════════════════

  async checkIp(ip: string): Promise<CheckIpResponse> {
    const names = [
      `SmartSIEM-Block-${ip}`,
      `SmartSIEM-Isolate-${ip}`,
      `SmartSIEM-Isolate-${ip}-out`,
      `SmartSIEM-Isolate-${ip}-in`,
    ];
    const found: unknown[] = [];
    for (const name of names) {
      const obj = await this.getAddressObject(name);
      if (obj) found.push(obj);
    }
    return { blocked: found.length > 0, rules: found };
  }

  async listRules(): Promise<FirewallActionResponse> {
    const policies = await this.getAllPolicies();
    const siemPolicies = policies.filter((p: any) =>
      String(p.name ?? '').startsWith(FortiGateAgentService.PREFIX),
    );
    return this.buildResponse(true, {
      action_requested: 'list_rules',
      action_applied: 'list_rules',
      scope: 'network_gateway',
      effect: `Retrieved ${siemPolicies.length} Smart SIEM firewall policies.`,
      limitations: ['Only SmartSIEM-prefixed policies are listed.'],
      rules: siemPolicies,
      count: siemPolicies.length,
    });
  }

  async deleteRule(name: string): Promise<FirewallActionResponse> {
    const prefix = FortiGateAgentService.PREFIX;
    const policies = await this.getAllPolicies();
    const matching = policies.filter((p: any) => {
      const n = String(p.name ?? '');
      return n.startsWith(prefix) && n.startsWith(name);
    });
    let deleted = 0;
    for (const p of matching) {
      if (await this.deletePolicy(String(p.name))) deleted++;
    }
    // Also remove address objects with the same prefix
    const addresses = await this.getAllAddressObjects();
    let addrsDeleted = 0;
    for (const a of addresses) {
      const n = String(a.name ?? '');
      if (n.startsWith(prefix) && n.startsWith(name)) {
        if (await this.deleteAddressObject(n)) addrsDeleted++;
      }
    }
    return this.buildResponse(true, {
      action_requested: 'delete_rule',
      action_applied: 'delete_rule',
      scope: 'network_gateway',
      effect: `Deleted ${deleted} polic${deleted === 1 ? 'y' : 'ies'} and ${addrsDeleted} address object(s) matching "${name}".`,
      limitations: ['Only SmartSIEM-prefixed objects are affected.'],
      rule_name: name,
      deleted_count: deleted,
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
      const res = await this.request<{ version?: string }>(
        'GET',
        '/api/v2/monitor/system/status',
      );
      if (res.status === 'success') {
        result.reachable = true;
        result.version = (res.results as any)?.version;
      } else {
        result.error = `HTTP ${res.http_status}: ${JSON.stringify(res.error ?? '')}`;
      }
    } catch (err: any) {
      result.error = err.message;
    }
    return result;
  }

  // ══════════════════════════════════════════════════
  //  FortiOS object helpers
  // ══════════════════════════════════════════════════

  private async ensureAddressObject(
    name: string,
    ip: string,
    comment: string,
  ): Promise<void> {
    const existing = await this.getAddressObject(name);
    const body = {
      name,
      type: 'ipmask',
      subnet: `${ip} 255.255.255.255`,
      comment: `Smart SIEM - ${comment}`,
    };
    if (existing) {
      const res = await this.request(
        'PUT',
        `/api/v2/cmdb/firewall/address/${name}`,
        body,
      );
      if (res.status !== 'success') {
        throw new Error(
          `FortiGate address object update failed: ${JSON.stringify(res.error ?? res)}`,
        );
      }
      return;
    }
    const res = await this.request(
      'POST',
      '/api/v2/cmdb/firewall/address',
      body,
    );
    if (res.status !== 'success') {
      throw new Error(
        `FortiGate address object create failed: ${JSON.stringify(res.error ?? res)}`,
      );
    }
  }

  private async getAddressObject(
    name: string,
  ): Promise<Record<string, unknown> | null> {
    const res = await this.request<any[]>(
      'GET',
      `/api/v2/cmdb/firewall/address?name=${encodeURIComponent(name)}`,
    );
    const results = res.results;
    if (!Array.isArray(results)) return null;
    return (
      (results.find((r: any) => r?.name === name) as
        | Record<string, unknown>
        | undefined) ?? null
    );
  }

  private async deleteAddressObject(name: string): Promise<boolean> {
    const res = await this.request(
      'DELETE',
      `/api/v2/cmdb/firewall/address/${encodeURIComponent(name)}`,
    );
    return res.status === 'success' || res.http_status === 404;
  }

  private async getAllAddressObjects(): Promise<any[]> {
    const res = await this.request<any[]>(
      'GET',
      '/api/v2/cmdb/firewall/address?vdom=root',
    );
    return Array.isArray(res.results) ? res.results : [];
  }

  private async ensureServiceObject(
    name: string,
    port: number,
    protocol: 'tcp' | 'udp',
    comment: string,
  ): Promise<void> {
    const existing = await this.getServiceObject(name);
    const body = {
      name,
      // FortiOS only offers the combined transport enum; the portrange
      // field selects the actual protocol (tcp-portrange / udp-portrange).
      protocol: 'TCP/UDP/UDP-Lite/SCTP',
      [`${protocol}-portrange`]: `${port}`,
      comment: `Smart SIEM - ${comment}`,
    };
    if (existing) {
      const res = await this.request(
        'PUT',
        `/api/v2/cmdb/firewall.service/custom/${name}`,
        body,
      );
      if (res.status !== 'success') {
        throw new Error(
          `FortiGate service object update failed: ${JSON.stringify(res.error ?? res)}`,
        );
      }
      return;
    }
    const res = await this.request(
      'POST',
      '/api/v2/cmdb/firewall.service/custom',
      body,
    );
    if (res.status !== 'success') {
      throw new Error(
        `FortiGate service object create failed: ${JSON.stringify(res.error ?? res)}`,
      );
    }
  }

  private async getServiceObject(
    name: string,
  ): Promise<Record<string, unknown> | null> {
    const res = await this.request<any[]>(
      'GET',
      `/api/v2/cmdb/firewall.service/custom?name=${encodeURIComponent(name)}`,
    );
    const results = res.results;
    if (!Array.isArray(results)) return null;
    return (
      (results.find((r: any) => r?.name === name) as
        | Record<string, unknown>
        | undefined) ?? null
    );
  }

  /**
   * Create or update a deny policy: srcaddr -> dstaddr is denied.
   * 'all' is the FortiOS built-in address object for any address.
   */
  private async ensurePolicy(
    policyName: string,
    srcAddrName: string,
    dstAddrName: string,
    serviceName: string | undefined,
  ): Promise<void> {
    const existing = await this.getPolicy(policyName);
    const body: Record<string, unknown> = {
      name: policyName,
      srcintf: [{ name: 'any' }],
      dstintf: [{ name: 'any' }],
      srcaddr: [{ name: srcAddrName }],
      dstaddr: [{ name: dstAddrName }],
      action: 'deny',
      schedule: 'always',
      service: [{ name: serviceName ?? 'ALL' }],
      logtraffic: 'all',
      comments: `Smart SIEM - deny ${srcAddrName} -> ${dstAddrName}`,
    };
    if (existing) {
      // FortiOS addresses firewall/policy objects by numeric policyid
      const policyKey = String((existing as any).policyid ?? policyName);
      const res = await this.request(
        'PUT',
        `/api/v2/cmdb/firewall/policy/${encodeURIComponent(policyKey)}`,
        body,
      );
      if (res.status !== 'success') {
        throw new Error(
          `FortiGate policy update failed: ${JSON.stringify(res.error ?? res)}`,
        );
      }
      return;
    }
    const res = await this.request(
      'POST',
      '/api/v2/cmdb/firewall/policy',
      body,
    );
    if (res.status !== 'success') {
      throw new Error(
        `FortiGate policy create failed: ${JSON.stringify(res.error ?? res)}`,
      );
    }
  }

  private async getPolicy(
    name: string,
  ): Promise<Record<string, unknown> | null> {
    const res = await this.request<any[]>(
      'GET',
      `/api/v2/cmdb/firewall/policy?name=${encodeURIComponent(name)}`,
    );
    const results = res.results;
    if (!Array.isArray(results)) return null;
    return (
      (results.find((r: any) => r?.name === name) as
        | Record<string, unknown>
        | undefined) ?? null
    );
  }

  private async getAllPolicies(): Promise<any[]> {
    const res = await this.request<any[]>(
      'GET',
      '/api/v2/cmdb/firewall/policy?vdom=root',
    );
    return Array.isArray(res.results) ? res.results : [];
  }

  private async deletePolicy(name: string): Promise<boolean> {
    // FortiOS requires the numeric policyid in the URL, not the name.
    const existing = await this.getPolicy(name);
    if (!existing) return true; // nothing to delete (idempotent)
    const policyKey = String((existing as any).policyid ?? name);
    const res = await this.request(
      'DELETE',
      `/api/v2/cmdb/firewall/policy/${encodeURIComponent(policyKey)}`,
    );
    return res.status === 'success' || res.http_status === 404;
  }

  // ══════════════════════════════════════════════════
  //  HTTP + response plumbing
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

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<FortiResponse<T>> {
    if (!this.apiToken) {
      this.logger.warn('[fortigate] No API token configured');
      return {
        status: 'error',
        http_status: 0,
        error: 'FORTIGATE_API_TOKEN not configured',
      };
    }

    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiToken}`,
      'Content-Type': 'application/json',
    };

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
      let data: FortiResponse<T>;
      try {
        data = JSON.parse(text) as FortiResponse<T>;
      } catch {
        data = { status: 'error', http_status: response.status, error: text };
      }
      data.http_status = response.status;
      return data;
    } catch (err: any) {
      this.logger.error(`[fortigate] ${method} ${path} failed: ${err.message}`);
      return { status: 'error', http_status: 0, error: err.message };
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
