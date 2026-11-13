import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { DetectionResult } from '../correlation/interfaces/detection-rule.interface';

export interface EntityRef {
  entity_type: string;
  value: string;
}

const AUTH_ACTIONS = /login|auth/i;

/**
 * Builds the entity relationship graph (Postgres-backed, no graph DB) from
 * Layer-1 incident evidence. Every incident contributes entity observations
 * and typed edges derived from its stored incident_events.
 */
@Injectable()
export class EntityGraphService {
  private readonly logger = new Logger(EntityGraphService.name);

  constructor(private readonly prisma: PrismaService) {}

  /** Entities mentioned by a detection result (ips/users/hosts). */
  static collectEntities(result: DetectionResult): EntityRef[] {
    const refs: EntityRef[] = [];
    for (const ip of result.related_entities.ips ?? []) {
      refs.push({ entity_type: 'IP', value: ip });
    }
    for (const user of result.related_entities.users ?? []) {
      refs.push({ entity_type: 'USER', value: user });
    }
    for (const host of result.related_entities.hosts ?? []) {
      refs.push({ entity_type: 'HOST', value: host });
    }
    return refs;
  }

  /** Upsert entity nodes + observations for one detection; returns entity ids. */
  async recordDetection(
    result: DetectionResult,
    incidentId: string,
  ): Promise<string[]> {
    const refs = EntityGraphService.collectEntities(result);
    if (refs.length === 0) return [];

    const observedAt = new Date();
    const ids: string[] = [];
    for (const ref of refs) {
      try {
        const entity = await this.upsertEntity(ref, observedAt);
        ids.push(entity.id);
        await this.prisma.entityObservation.create({
          data: {
            entity_id: entity.id,
            incident_id: incidentId,
            rule_id: result.rule_id,
            observed_at: observedAt,
            attributes: {
              severity: result.severity,
              confidence_score: result.confidence_score,
              summary: result.summary,
            },
          },
        });
      } catch (err) {
        this.logger.warn(
          `Failed to record entity ${ref.entity_type}:${ref.value}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return ids;
  }

  /**
   * Build typed edges from the incident's stored events:
   *   IP → HOST  CONTACTED        (any event with source_ip + hostname)
   *   IP → USER  USED_ACCOUNT     (auth-ish events with user_principal)
   *   USER → HOST AUTHENTICATED_ON (auth-ish events)
   */
  async recordEdges(incidentId: string, ruleId: string): Promise<void> {
    const events = await this.prisma.incidentEvent.findMany({
      where: { incident_id: incidentId },
    });
    if (events.length === 0) return;

    const now = new Date();
    const seen = new Set<string>();

    for (const ev of events) {
      const ip = ev.source_ip;
      const host = ev.hostname;
      const user = ev.user_principal;
      const isAuth = !!ev.action && AUTH_ACTIONS.test(ev.action);

      const pairs: Array<[string, string, string, string, string] | null> = [
        ip && host ? ['IP', ip, 'HOST', host, 'CONTACTED'] : null,
        ip && user && isAuth ? ['IP', ip, 'USER', user, 'USED_ACCOUNT'] : null,
        user && host && isAuth
          ? ['USER', user, 'HOST', host, 'AUTHENTICATED_ON']
          : null,
      ];

      for (const p of pairs) {
        if (!p) continue;
        const [srcType, srcValue, dstType, dstValue, rel] = p;
        const key = `${srcType}|${srcValue}|${rel}|${dstType}|${dstValue}`;
        if (seen.has(key)) continue;
        seen.add(key);

        try {
          const src = await this.upsertEntity(
            { entity_type: srcType, value: srcValue },
            now,
          );
          const dst = await this.upsertEntity(
            { entity_type: dstType, value: dstValue },
            now,
          );
          await this.upsertEdge(src.id, dst.id, rel, ruleId, incidentId, now);
        } catch (err) {
          this.logger.warn(
            `Failed to record edge ${key}: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }
  }

  private async upsertEntity(ref: EntityRef, seenAt: Date) {
    return this.prisma.entity.upsert({
      where: {
        entities_type_value_key: {
          entity_type: ref.entity_type,
          value: ref.value,
        },
      },
      create: {
        entity_type: ref.entity_type,
        value: ref.value,
        first_seen_at: seenAt,
        last_seen_at: seenAt,
      },
      update: { last_seen_at: seenAt },
    });
  }

  private async upsertEdge(
    sourceId: string,
    targetId: string,
    relationship: string,
    ruleId: string,
    incidentId: string,
    seenAt: Date,
  ) {
    const existing = await this.prisma.entityEdge.findUnique({
      where: {
        entity_edges_unique: {
          source_entity_id: sourceId,
          target_entity_id: targetId,
          relationship,
        },
      },
    });
    if (existing) {
      return this.prisma.entityEdge.update({
        where: { id: existing.id },
        data: {
          last_seen_at: seenAt,
          observation_count: { increment: 1 },
          last_rule_id: ruleId,
          last_incident_id: incidentId,
        },
      });
    }
    return this.prisma.entityEdge.create({
      data: {
        source_entity_id: sourceId,
        target_entity_id: targetId,
        relationship,
        first_seen_at: seenAt,
        last_seen_at: seenAt,
        observation_count: 1,
        last_rule_id: ruleId,
        last_incident_id: incidentId,
      },
    });
  }
}
