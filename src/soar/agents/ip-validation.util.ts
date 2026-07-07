import * as net from 'node:net';

// ============================================================
//  IpValidationUtil — Validation syntaxique et sémantique
//  des adresses IP avant toute opération de blocage.
//
//  Protège les infrastructures critiques (SIEM, AD, DC)
//  contre les blocages accidentels.
// ============================================================

let protectedIps: string[] | null = null;

function getProtectedIps(): string[] {
  if (protectedIps) return protectedIps;

  const list = new Set<string>();

  // Variables d'environnement dédiées
  const fromEnv =
    process.env.SOAR_FIREWALL_PROTECTED_IPS?.split(',').filter(Boolean) ?? [];
  for (const ip of fromEnv) list.add(ip.trim());

  // Hôte SIEM lui-même
  if (process.env.HOST_IP) list.add(process.env.HOST_IP);

  // Contrôleur de domaine / AD
  if (process.env.SOAR_FIREWALL_PROTECTED_AD_DC_IP)
    list.add(process.env.SOAR_FIREWALL_PROTECTED_AD_DC_IP);

  // localhost explicite — ne jamais bloquer le loopback
  list.add('127.0.0.1');
  list.add('::1');

  protectedIps = [...list];
  return protectedIps;
}

/** Remet à zéro le cache des IP protégées (utile en test) */
export function resetProtectedIpCache(): void {
  protectedIps = null;
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Valide une adresse IP avant blocage.
 *
 * 1. Validation syntaxique — rejette les chaînes malformées
 * 2. Validation sémantique — refuse les IP protégées configurées
 */
export function validateBlockIp(ip: string): ValidationResult {
  if (!ip || typeof ip !== 'string') {
    return { valid: false, error: 'IP address is required' };
  }

  const trimmed = ip.trim();

  // Validation syntaxique via le module net natif
  const isValidV4 = net.isIPv4(trimmed);
  const isValidV6 = net.isIPv6(trimmed);

  if (!isValidV4 && !isValidV6) {
    return {
      valid: false,
      error: `Invalid IP address format: "${ip}"`,
    };
  }

  // Normaliser l'IP pour la comparaison (net.isIPv4 accepte les espaces,
  // on prend la version trim)
  const normalized = trimmed;

  // Validation sémantique — liste de protection
  const protectedList = getProtectedIps();
  if (protectedList.includes(normalized)) {
    return {
      valid: false,
      error: `Cannot block protected IP: ${normalized}. This address is reserved for critical infrastructure.`,
    };
  }

  return { valid: true };
}
