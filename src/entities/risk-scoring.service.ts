import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/** Spec §5 thresholds */
export const RISK_BANDS = [
  { min: 0, max: 19, label: 'INFORMATIONAL' },
  { min: 20, max: 39, label: 'LOW' },
  { min: 40, max: 59, label: 'MEDIUM' },
  { min: 60, max: 79, label: 'HIGH' },
  { min: 80, max: 100, label: 'CRITICAL' },
] as const;

/** Illustrative per-rule weights (spec §5); overridable via risk_scoring_config.weights */
export const DEFAULT_RISK_WEIGHTS: Record<string, number> = {
  R001: 20, // brute force
  R002: 25, // pass-the-hash / lateral movement
  R003: 35, // data exfiltration
  R004: 30, // log clearing
  R005: 10, // port scan / recon
  R006: 20, // ssh brute force
  R007: 15, // password spraying
  R008: 30, // successful login after failures
  R010: 25, // suspicious admin account
  R011: 30, // suspicious PowerShell
  R013: 30, // privilege escalation
  R014: 20, // sudo abuse
  R015: 10, // scheduled task persistence
  R018: 35, // AV/EDR disablement
  R019: 20, // firewall modification
  R020: 30, // suspicious file deletion
  C001: 40, // recon → access
  C002: 35, // brute force → compromise
  C003: 30, // lateral movement
  C004: 40, // exfil after access
  C005: 45, // defense evasion → theft
  C006: 30, // rogue admin account
  C007: 35, // malware + persistence
  C008: 40, // credential theft → movement
  C009: 30, // recon → database
  C010: 50, // ransomware
};

const SEVERITY_FALLBACK: Record<string, number> = {
  INFO: 5,
  WARNING: 10,
  HIGH: 20,
  CRITICAL: 30,
};

export function riskBand(score: number): string {
  for (const band of RISK_BANDS) {
    if (score >= band.min && score <= band.max) return band.label;
  }
  return 'CRITICAL';
}

interface RiskConfig {
  decayHalfLifeHours: number;
  maxScore: number;
  weights: Record<string, number>;
}

/**
 * Decaying, time-aware entity risk score (spec §5).
 *
 * score(t) = min(max, score(t-1) * 0.5^(dt / half_life) + points)
 *
 * Rule-deduplicated: one (entity, rule, incident) triple contributes once,
 * enforced by the entity_risk_events unique constraint.
 */
@Injectable()
export class RiskScoringService {
  private readonly logger = new Logger(RiskScoringService.name);
  private cachedConfig: { config: RiskConfig; loadedAt: number } | null = null;
  private static readonly CACHE_MS = 60_000;

  constructor(private readonly prisma: PrismaService) {}

  async getConfig(): Promise<RiskConfig> {
    if (
      this.cachedConfig &&
      Date.now() - this.cachedConfig.loadedAt < RiskScoringService.CACHE_MS
    ) {
      return this.cachedConfig.config;
    }

    let row = await this.prisma.riskScoringConfig.findUnique({
      where: { id: 1 },
    });
    if (!row) {
      row = await this.prisma.riskScoringConfig.create({
        data: { id: 1, weights: DEFAULT_RISK_WEIGHTS as any },
      });
    }

    const config: RiskConfig = {
      decayHalfLifeHours: row.decay_half_life_hours,
      maxScore: row.max_score,
      weights: {
        ...DEFAULT_RISK_WEIGHTS,
        ...((row.weights as Record<string, number> | null) ?? {}),
      },
    };
    this.cachedConfig = { config, loadedAt: Date.now() };
    return config;
  }

  /** Apply one detection's contribution to an entity's risk score. */
  async applyDetection(
    entityId: string,
    ruleId: string,
    incidentId: string,
    severity: string,
    observedAt: Date,
  ): Promise<{
    score: number;
    band: string;
    points: number;
    counted: boolean;
  }> {
    const config = await this.getConfig();
    const points =
      config.weights[ruleId] ??
      SEVERITY_FALLBACK[severity] ??
      SEVERITY_FALLBACK.WARNING;

    const entity = await this.prisma.entity.findUniqueOrThrow({
      where: { id: entityId },
      select: { risk_score: true, risk_updated_at: true },
    });

    // Rule-dedup: unique (entity, rule, incident) — a replayed/duplicate
    // detection of the same incident must not add points twice.
    try {
      await this.prisma.entityRiskEvent.create({
        data: {
          entity_id: entityId,
          rule_id: ruleId,
          incident_id: incidentId,
          points,
          observed_at: observedAt,
        },
      });
    } catch (err: any) {
      if (err?.code === 'P2002') {
        return {
          score: entity.risk_score,
          band: riskBand(entity.risk_score),
          points: 0,
          counted: false,
        };
      }
      throw err;
    }

    let decayed = entity.risk_score;
    if (entity.risk_updated_at) {
      const elapsedMs = Math.max(
        0,
        observedAt.getTime() - entity.risk_updated_at.getTime(),
      );
      const halfLifeMs = config.decayHalfLifeHours * 3600_000;
      decayed = entity.risk_score * Math.pow(0.5, elapsedMs / halfLifeMs);
    }

    const newScore = Math.min(config.maxScore, decayed + points);

    await this.prisma.entity.update({
      where: { id: entityId },
      data: {
        risk_score: newScore,
        risk_updated_at: observedAt,
        observation_count: { increment: 1 },
        last_seen_at: observedAt,
      },
    });

    this.logger.debug(
      `Risk ${ruleId} +${points} → ${newScore.toFixed(1)} (${riskBand(newScore)}) for entity ${entityId}`,
    );

    return { score: newScore, band: riskBand(newScore), points, counted: true };
  }

  /** Current risk for an entity value (for assertions / API). */
  async getRisk(entityType: string, value: string) {
    const entity = await this.prisma.entity.findUnique({
      where: { entities_type_value_key: { entity_type: entityType, value } },
    });
    if (!entity) return null;
    return {
      score: entity.risk_score,
      band: riskBand(entity.risk_score),
      entity,
    };
  }
}
