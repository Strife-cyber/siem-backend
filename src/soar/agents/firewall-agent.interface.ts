// ============================================================
//  IFirewallAgent — Abstraction unifiée pour tous les
//  connecteurs pare-feu (pfSense, Windows Defender, …)
//
//  Chaque méthode retourne une structure normalisée contenant
//  le provider, l'action effectuée, le scope, l'effet textuel,
//  les limitations et les métadonnées d'audit.
// ============================================================

// ───── Métadonnées d'audit (traçabilité SOAR) ─────
export interface FirewallAuditMeta {
  incident_id?: string;
  playbook_name?: string;
  attack_type?: string;
  severity?: string;
  mode?: 'AUTO' | 'CONFIRM';
}

// ───── Réponse unifiée pour les actions de modification ─────
export interface FirewallActionResponse {
  /** Nom du provider, ex. "windows_defender" ou "pfsense" */
  provider: string;
  /** Action demandée, ex. "block_ip" */
  action_requested: string;
  /** Action réellement exécutée */
  action_applied: string;
  /** Périmètre, ex. "local_windows_host_inbound" ou "network_gateway_inbound" */
  scope: string;
  /** Description en langage naturel de l'effet produit */
  effect: string;
  /** Liste des contraintes connues */
  limitations: string[];
  /** Métadonnées de traçabilité */
  audit: FirewallAuditMeta;
  /** Champs spécifiques à l'action (ip, rule_name, port, protocol, etc.) */
  [key: string]: unknown;
}

// ───── Réponse pour check-ip ─────
export interface CheckIpResponse {
  blocked: boolean;
  rules: unknown[];
}

// ───── Réponse pour health check ─────
export interface FirewallHealth {
  provider: string;
  configured: boolean;
  reachable: boolean;
  version?: string;
  error?: string;
}

// ───── Injection token NestJS ─────
export const FIREWALL_AGENT = 'FIREWALL_AGENT';

// ───── Interface principale ─────
export interface IFirewallAgent {
  /** Identifiant textuel du provider (ex. "windows_defender") */
  readonly provider: string;

  /** true si les variables d'environnement nécessaires sont présentes */
  readonly isConfigured: boolean;

  // ── Actions de blocage ──

  /** Bloquer une IP entrante */
  blockIp(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse>;

  /** Bloquer un port spécifique depuis une IP source */
  blockPort(
    ip: string,
    port: number,
    protocol: 'tcp' | 'udp',
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse>;

  /** Isolation bidirectionnelle d'un hôte */
  isolateHost(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse>;

  // ── Actions de vérification ──

  /** Vérifier si une IP est bloquée */
  checkIp(ip: string): Promise<CheckIpResponse>;

  // ── Actions de déblocage ──

  /** Lever tous les blocages associés à une IP */
  unblockIp(ip: string): Promise<FirewallActionResponse>;

  /** Lister toutes les règles gérées par Smart SIEM */
  listRules(): Promise<FirewallActionResponse>;

  /** Supprimer une règle par son nom */
  deleteRule(name: string): Promise<FirewallActionResponse>;

  // ── Health ──

  /** Vérifier l'état de la connexion au pare-feu */
  healthCheck(): Promise<FirewallHealth>;
}
