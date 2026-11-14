import { sequenceCorrelation } from './attack-correlation.rules';
import type { PrismaService } from '../../prisma/prisma.service';

function fakePrisma(incidents: Array<Record<string, unknown>>): PrismaService {
  return {
    incident: {
      findMany: jest.fn().mockResolvedValue(incidents),
    },
  } as unknown as PrismaService;
}

function incident(
  id: string,
  ruleId: string,
  minute: number,
  entities: { ips?: string[]; users?: string[]; hosts?: string[] },
): Record<string, unknown> {
  return {
    id,
    rule_id: ruleId,
    severity: 'HIGH',
    triggered_at: new Date(Date.UTC(2026, 10, 13, 12, minute, 0)),
    related_entities: entities,
  };
}

describe('sequenceCorrelation', () => {
  const since = new Date(Date.UTC(2026, 10, 13, 11, 0, 0));

  it('backtracks past a stage candidate that dead-ends the chain', async () => {
    // Greedy first-match would commit to 'x' at stage 1 and never reach a
    // complete chain; backtracking tries 'y' and completes via 'z'.
    const rule = sequenceCorrelation({
      id: 'C-TEST',
      name: 'Test chain',
      stages: [['RA'], ['RB'], ['RC']],
      severity: 'HIGH',
      confidence: 50,
      summary: (chain) => chain.map((c) => c.id).join('>'),
    });
    const incidents = [
      incident('s', 'RA', 0, {
        ips: ['10.0.0.1'],
        users: ['alice'],
        hosts: ['h1'],
      }),
      // Shares host h1 with the start, but nothing with 'z' — dead end.
      incident('x', 'RB', 1, {
        ips: ['10.0.0.9'],
        users: ['bob'],
        hosts: ['h1'],
      }),
      // Shares user alice with the start and everything with 'z'.
      incident('y', 'RB', 2, {
        ips: ['10.0.0.2'],
        users: ['alice'],
        hosts: ['h2'],
      }),
      incident('z', 'RC', 3, {
        ips: ['10.0.0.2'],
        users: ['alice'],
        hosts: ['h2'],
      }),
    ];

    const results = await rule.detect(fakePrisma(incidents), since);
    expect(results).toHaveLength(1);
    expect(results[0].prerequisite_incident_ids).toEqual(['s', 'y', 'z']);
  });

  it('does not fire when no stage candidate shares an entity', async () => {
    const rule = sequenceCorrelation({
      id: 'C-TEST',
      name: 'Test chain',
      stages: [['RA'], ['RB'], ['RC']],
      severity: 'HIGH',
      confidence: 50,
      summary: (chain) => chain.map((c) => c.id).join('>'),
    });
    const incidents = [
      incident('s', 'RA', 0, {
        ips: ['10.0.0.1'],
        users: ['alice'],
        hosts: ['h1'],
      }),
      incident('x', 'RB', 1, {
        ips: ['10.0.0.9'],
        users: ['bob'],
        hosts: ['h9'],
      }),
      incident('z', 'RC', 2, {
        ips: ['10.0.0.2'],
        users: ['carol'],
        hosts: ['h2'],
      }),
    ];

    const results = await rule.detect(fakePrisma(incidents), since);
    expect(results).toHaveLength(0);
  });

  it('still matches two-stage chains within the time window', async () => {
    const rule = sequenceCorrelation({
      id: 'C-TEST',
      name: 'Test chain',
      stages: [['R011'], ['R015', 'R017']],
      severity: 'HIGH',
      confidence: 50,
      summary: (chain) => chain.map((c) => c.id).join('>'),
    });
    const incidents = [
      incident('s', 'R011', 0, {
        ips: ['10.0.0.1'],
        users: ['alice'],
        hosts: ['h1'],
      }),
      incident('y', 'R017', 2, {
        ips: ['10.0.0.1'],
        users: ['alice'],
        hosts: ['h1'],
      }),
      // Outside the 30-minute window from the start — must not chain.
      incident('late', 'R015', 31, {
        ips: ['10.0.0.1'],
        users: ['alice'],
        hosts: ['h1'],
      }),
    ];

    const results = await rule.detect(fakePrisma(incidents), since);
    expect(results).toHaveLength(1);
    expect(results[0].prerequisite_incident_ids).toEqual(['s', 'y']);
  });
});
