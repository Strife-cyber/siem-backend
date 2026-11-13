/**
 * Attack-simulation runner (TDIR Phase 0 gate).
 *
 * Runs a scenario end-to-end against the live stack:
 *
 *   1. Activates the correlation rules the scenario requires.
 *   2. Provisions a temporary API key for log ingestion.
 *   3. Replays the scenario's raw log fixtures through the collector's
 *      `replay` binary — the real `normalize_record` + shipper path —
 *      into `POST /api/v1/logs`.
 *   4. Triggers a correlation cycle on the BullMQ `correlation` queue.
 *   5. Asserts on incidents / playbook executions / SOAR actions created
 *      during the run and prints a PASS/FAIL report.
 *
 * Prerequisites:
 *   - Stack running:  docker compose -f docker-compose.yml \
 *         -f docker-compose.simulation.yml up -d --build
 *   - DB migrated + rules seeded:  npm run seed:rules (inside app container
 *     or locally with DATABASE_URL pointed at the exposed port)
 *   - Collector replay binary built:  cargo build --bin replay
 *     in ../siem-collector
 *
 * Usage:
 *   npm run simulate -- simulation/scenarios/benign-baseline.json
 *   npm run simulate -- simulation/scenarios/r001-brute-force.json
 *
 * Options:
 *   --api-url URL        Backend base URL (default http://localhost:3000)
 *   --collector-bin PATH Replay binary (default ../siem-collector/target/debug/replay)
 *   --db-url URL         Postgres URL (default postgresql://siem:siem_password@localhost:5432/siem_db)
 *   --redis-host HOST    Redis host (default localhost)
 *   --redis-port PORT    Redis port (default 6379)
 *   --api-key KEY        Reuse an existing ingestion API key
 *   --timeout SEC        Max seconds to wait for expectations (default 90)
 *   --settle-ms MS       Wait after replay before triggering the cycle (default 5000)
 *   --batch-ms MS        Collector shipper batch interval (default 500)
 *   --ship-timeout-secs N  Max seconds the collector may spend shipping (default 60)
 */

import 'dotenv/config';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';
import { Queue } from 'bullmq';

const execFileAsync = promisify(execFile);

// ─────────────────────────────────────────────────────────────
// Scenario types
// ─────────────────────────────────────────────────────────────

interface ScenarioLine {
  offset_seconds?: number;
  raw: string;
}
interface ScenarioSource {
  source_type: string;
  hostname: string;
  lines: ScenarioLine[];
}
interface ExpectIncident {
  rule_id: string;
  min_severity?: string;
  min_count?: number;
}
interface ExpectPlaybook {
  playbook_name: string;
  status?: string;
  min_count?: number;
}
interface ExpectSoarAction {
  action_type: string;
  min_count?: number;
}
interface ExpectEntityRisk {
  entity_type: string;
  value: string;
  min_score: number;
}
interface ExpectEntityEdge {
  source_type: string;
  source_value: string;
  relationship: string;
  target_type: string;
  target_value: string;
}
interface AssertBlock {
  expect_incidents?: ExpectIncident[];
  expect_no_incidents_for_rules?: string[];
  expect_no_high_or_critical_incidents?: boolean;
  expect_playbook_executions?: ExpectPlaybook[];
  expect_soar_actions?: ExpectSoarAction[];
  expect_entity_risk?: ExpectEntityRisk[];
  expect_entity_edges?: ExpectEntityEdge[];
}
interface Scenario {
  name: string;
  description?: string;
  base_time: string;
  requires_rules?: string[];
  sources: ScenarioSource[];
  assert: AssertBlock;
}

// ─────────────────────────────────────────────────────────────
// CLI args
// ─────────────────────────────────────────────────────────────

interface CliOptions {
  scenarioPath: string;
  apiUrl: string;
  collectorBin: string;
  dbUrl: string;
  redisHost: string;
  redisPort: number;
  apiKey?: string;
  timeoutSec: number;
  settleMs: number;
  batchMs: number;
  shipTimeoutSecs: number;
}

function parseArgs(argv: string[]): CliOptions {
  const positional = argv.filter(
    (a) => !a.startsWith('--') && !isValueOfFlag(argv, a),
  );
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const scenarioPath = positional[0];
  if (!scenarioPath) {
    console.error('Usage: npm run simulate -- <scenario.json> [options]');
    process.exit(2);
  }
  return {
    scenarioPath,
    apiUrl: (get('--api-url') ?? 'http://localhost:3000').replace(/\/+$/, ''),
    collectorBin:
      get('--collector-bin') ??
      path.resolve(process.cwd(), '../siem-collector/target/debug/replay'),
    dbUrl:
      get('--db-url') ??
      'postgresql://siem:siem_password@localhost:5432/siem_db',
    redisHost: get('--redis-host') ?? 'localhost',
    redisPort: Number(get('--redis-port') ?? '6379'),
    apiKey: get('--api-key'),
    timeoutSec: Number(get('--timeout') ?? '90'),
    settleMs: Number(get('--settle-ms') ?? '5000'),
    batchMs: Number(get('--batch-ms') ?? '500'),
    shipTimeoutSecs: Number(get('--ship-timeout-secs') ?? '60'),
  };
}

function isValueOfFlag(argv: string[], value: string): boolean {
  const flagsWithValues = [
    '--api-url',
    '--collector-bin',
    '--db-url',
    '--redis-host',
    '--redis-port',
    '--api-key',
    '--timeout',
    '--settle-ms',
    '--batch-ms',
  ];
  return flagsWithValues.some(
    (f) => argv[argv.indexOf(f) + 1] === value && argv.includes(f),
  );
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  INFO: 1,
  NOTICE: 2,
  WARNING: 3,
  HIGH: 4,
  CRITICAL: 5,
  EMERGENCY: 6,
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface CheckResult {
  label: string;
  ok: boolean;
  detail: string;
}

// ─────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const scenarioPath = path.resolve(process.cwd(), opts.scenarioPath);
  const scenario: Scenario = JSON.parse(
    await import('node:fs').then((fs) =>
      fs.promises.readFile(scenarioPath, 'utf8'),
    ),
  );

  console.log(`\n=== Simulation: ${scenario.name} ===`);
  if (scenario.description) console.log(scenario.description);
  console.log(`Scenario file: ${scenarioPath}`);

  const adapter = new PrismaPg({ connectionString: opts.dbUrl });
  const prisma = new PrismaClient({ adapter });
  const correlationQueue = new Queue('correlation', {
    connection: { host: opts.redisHost, port: opts.redisPort },
  });

  const results: CheckResult[] = [];
  const runStart = new Date();

  try {
    // 1. Activate required rules
    const required = scenario.requires_rules ?? [];
    if (required.length > 0) {
      const existing = await prisma.correlationRule.findMany({
        where: { id: { in: required } },
        select: { id: true, is_active: true },
      });
      const found = new Set(existing.map((r) => r.id));
      for (const ruleId of required) {
        if (!found.has(ruleId)) {
          results.push({
            label: `rule ${ruleId} exists`,
            ok: false,
            detail:
              'not found in correlation_rules — run `npm run seed:rules` first',
          });
        }
      }
      await prisma.correlationRule.updateMany({
        where: { id: { in: required } },
        data: { is_active: true },
      });
      console.log(`Activated rules: ${required.join(', ')}`);
    }

    // 2. Provision API key
    // NOTE: the prefix (first 8 chars) must be unique per key — the API-key
    // guard looks keys up by prefix, so keys sharing a prefix break auth.
    let apiKey = opts.apiKey;
    if (!apiKey) {
      const rawKey = `sim_${crypto.randomBytes(28).toString('hex')}`;
      const keyPrefix = rawKey.substring(0, 8);
      const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
      await prisma.apiKey.create({
        data: {
          name: `simulation-${scenario.name}`,
          key_hash: keyHash,
          key_prefix: keyPrefix,
        },
      });
      apiKey = rawKey;
      console.log('Provisioned temporary ingestion API key.');
    }

    // 3. Replay scenario through the collector's real pipeline
    console.log(
      `Replaying ${scenario.sources.length} source(s) through collector...`,
    );
    const { stdout, stderr } = await execFileAsync(
      opts.collectorBin,
      [
        scenarioPath,
        '--endpoint',
        `${opts.apiUrl}/api/v1/logs`,
        '--api-key',
        apiKey,
        '--batch-ms',
        String(opts.batchMs),
        '--ship-timeout-secs',
        String(opts.shipTimeoutSecs),
      ],
      { timeout: (opts.shipTimeoutSecs + 30) * 1000 },
    );
    if (stdout.trim()) console.log(stdout.trim());
    if (stderr.trim()) console.log(stderr.trim());
    results.push({
      label: 'collector replay',
      ok: true,
      detail:
        'raw fixtures normalized + shipped via the collector shipper path',
    });

    // 4. Let the logs queue + ES indexing settle, then trigger a cycle
    console.log(`Waiting ${opts.settleMs}ms for ingestion to settle...`);
    await sleep(opts.settleMs);
    await correlationQueue.add('cycle', {}, { removeOnComplete: true });
    console.log('Correlation cycle enqueued.');

    // 5. Poll for expectations
    const assertBlock = scenario.assert ?? {};
    const positiveExpectations =
      (assertBlock.expect_incidents?.length ?? 0) +
      (assertBlock.expect_playbook_executions?.length ?? 0) +
      (assertBlock.expect_soar_actions?.length ?? 0) +
      (assertBlock.expect_entity_risk?.length ?? 0) +
      (assertBlock.expect_entity_edges?.length ?? 0);

    const deadline = Date.now() + opts.timeoutSec * 1000;
    // Scenarios with no positive expectations only need one cycle to have run.
    const quietWaitMs =
      positiveExpectations === 0 ? 15_000 : opts.timeoutSec * 1000;
    const quietDeadline = Date.now() + quietWaitMs;

    let incidents: any[] = [];
    let executions: any[] = [];
    let actions: any[] = [];
    let entities: any[] = [];
    let edges: any[] = [];

    const fetchState = async () => {
      [incidents, executions, actions, entities, edges] = await Promise.all([
        prisma.incident.findMany({
          where: { triggered_at: { gte: runStart } },
        }),
        prisma.playbookExecution.findMany({
          where: { initiated_at: { gte: runStart } },
        }),
        prisma.soarAction.findMany({
          where: { created_at: { gte: runStart } },
        }),
        prisma.entity.findMany({ where: { last_seen_at: { gte: runStart } } }),
        prisma.entityEdge.findMany({
          where: { last_seen_at: { gte: runStart } },
          include: { source: true, target: true },
        }),
      ]);
    };

    const positivesMet = () => {
      for (const exp of assertBlock.expect_incidents ?? []) {
        const count = incidents.filter(
          (i) =>
            i.rule_id === exp.rule_id &&
            severityRank(i.severity) >=
              severityRank(exp.min_severity ?? 'INFO'),
        ).length;
        if (count < (exp.min_count ?? 1)) return false;
      }
      for (const exp of assertBlock.expect_playbook_executions ?? []) {
        const count = executions.filter(
          (e) =>
            e.playbook_name === exp.playbook_name &&
            (!exp.status || e.status === exp.status),
        ).length;
        if (count < (exp.min_count ?? 1)) return false;
      }
      for (const exp of assertBlock.expect_soar_actions ?? []) {
        const count = actions.filter(
          (a) => a.action_type === exp.action_type,
        ).length;
        if (count < (exp.min_count ?? 1)) return false;
      }
      return true;
    };

    for (;;) {
      await fetchState();
      if (positiveExpectations > 0 && positivesMet()) break;
      if (positiveExpectations === 0 && Date.now() >= quietDeadline) break;
      if (Date.now() >= deadline) break;
      await sleep(2000);
    }

    // Grace period so late-arriving cycle results are captured
    await sleep(3000);
    await fetchState();

    // 6. Evaluate assertions
    for (const exp of assertBlock.expect_incidents ?? []) {
      const matching = incidents.filter((i) => i.rule_id === exp.rule_id);
      const qualifying = matching.filter(
        (i) =>
          severityRank(i.severity) >= severityRank(exp.min_severity ?? 'INFO'),
      );
      const minCount = exp.min_count ?? 1;
      results.push({
        label: `incident ${exp.rule_id} (>= ${exp.min_severity ?? 'INFO'}, count >= ${minCount})`,
        ok: qualifying.length >= minCount,
        detail: `${qualifying.length} found (all severities: ${matching.map((i) => i.severity).join(', ') || 'none'})`,
      });
    }

    for (const ruleId of assertBlock.expect_no_incidents_for_rules ?? []) {
      const matching = incidents.filter((i) => i.rule_id === ruleId);
      results.push({
        label: `no incident for ${ruleId}`,
        ok: matching.length === 0,
        detail:
          matching.length === 0 ? 'none created' : `${matching.length} created`,
      });
    }

    if (assertBlock.expect_no_high_or_critical_incidents) {
      const severe = incidents.filter(
        (i) => severityRank(i.severity) >= severityRank('HIGH'),
      );
      results.push({
        label: 'no HIGH/CRITICAL incidents',
        ok: severe.length === 0,
        detail:
          severe.length === 0
            ? 'clean'
            : severe.map((i) => `${i.rule_id}:${i.severity}`).join(', '),
      });
    }

    for (const exp of assertBlock.expect_playbook_executions ?? []) {
      const matching = executions.filter(
        (e) =>
          e.playbook_name === exp.playbook_name &&
          (!exp.status || e.status === exp.status),
      );
      const minCount = exp.min_count ?? 1;
      results.push({
        label: `playbook ${exp.playbook_name}${exp.status ? ` (${exp.status})` : ''} count >= ${minCount}`,
        ok: matching.length >= minCount,
        detail: `${matching.length} found; statuses: ${executions.map((e) => `${e.playbook_name}=${e.status}`).join(', ') || 'none'}`,
      });
    }

    for (const exp of assertBlock.expect_soar_actions ?? []) {
      const matching = actions.filter((a) => a.action_type === exp.action_type);
      const minCount = exp.min_count ?? 1;
      results.push({
        label: `SOAR action ${exp.action_type} count >= ${minCount}`,
        ok: matching.length >= minCount,
        detail: `${matching.length} found`,
      });
    }

    for (const exp of assertBlock.expect_entity_risk ?? []) {
      const entity = entities.find(
        (e) => e.entity_type === exp.entity_type && e.value === exp.value,
      );
      results.push({
        label: `entity risk ${exp.entity_type}:${exp.value} >= ${exp.min_score}`,
        ok: !!entity && entity.risk_score >= exp.min_score,
        detail: entity
          ? `score=${entity.risk_score.toFixed(1)}`
          : `no entity ${exp.entity_type}:${exp.value} seen since run start`,
      });
    }

    for (const exp of assertBlock.expect_entity_edges ?? []) {
      const matching = edges.filter(
        (e) =>
          e.relationship === exp.relationship &&
          e.source?.entity_type === exp.source_type &&
          e.source?.value === exp.source_value &&
          e.target?.entity_type === exp.target_type &&
          e.target?.value === exp.target_value,
      );
      results.push({
        label: `entity edge ${exp.source_type}:${exp.source_value} -[${exp.relationship}]-> ${exp.target_type}:${exp.target_value}`,
        ok: matching.length >= 1,
        detail:
          matching.length >= 1
            ? `${matching.length} edge(s) found`
            : `edges seen: ${edges.map((e) => `${e.source?.entity_type}:${e.source?.value}-[${e.relationship}]->${e.target?.entity_type}:${e.target?.value}`).join(', ') || 'none'}`,
      });
    }

    // 7. Report
    console.log('\n── Results ──────────────────────────────');
    let failures = 0;
    for (const r of results) {
      const mark = r.ok ? 'PASS' : 'FAIL';
      if (!r.ok) failures += 1;
      console.log(`[${mark}] ${r.label}${r.ok ? '' : ` — ${r.detail}`}`);
    }
    console.log('──────────────────────────────────────────');
    console.log(
      failures === 0
        ? `\nSCENARIO PASSED: ${scenario.name}`
        : `\nSCENARIO FAILED: ${scenario.name} (${failures} assertion(s))`,
    );
    if (failures > 0) {
      console.log(
        '\nTip: correlation deduplicates identical detections for 5 minutes.',
      );
      console.log(
        'If you re-ran this scenario recently, reset the DB (docker compose down -v) and re-seed.',
      );
    }
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
    await correlationQueue.close();
    await prisma.$disconnect();
  }
}

function severityRank(severity: string | null | undefined): number {
  if (!severity) return 0;
  return SEVERITY_RANK[severity.toUpperCase()] ?? 0;
}

main().catch((err) => {
  console.error('Simulation runner error:', err);
  process.exit(2);
});
