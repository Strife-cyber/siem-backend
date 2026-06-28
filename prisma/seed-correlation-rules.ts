/**
 * Seed the 4 MITRE ATT&CK correlation rules into the database.
 *
 * Run with: npx tsx prisma/seed-correlation-rules.ts
 * Or via Docker: docker exec siem-app npm run seed:rules
 */

import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';
import 'dotenv/config';

const RULES = [
  {
    id: 'R001',
    name: 'SSH/Windows Brute Force',
    tactic: 'TA0001',
    technique: 'T1110',
    definition: {
      time_window_seconds: 60,
      interval_seconds: 60,
      threshold: 5,
      max_time_span_seconds: 45,
      source_types: ['linux_auth', 'windows_security'],
      actions: ['login'],
      outcomes: ['failure'],
    },
    confidence_weight: 80,
    is_active: false,
  },
  {
    id: 'R002',
    name: 'Lateral Movement (Pass-the-Hash)',
    tactic: 'TA0008',
    technique: 'T1550',
    definition: {
      time_window_seconds: 300,
      interval_seconds: 120,
      threshold: 1,
      source_types: ['windows_security'],
      actions: ['login', 'authenticate'],
      outcomes: ['success'],
      params: { baseline_redis_key: 'pth:baseline' },
    },
    confidence_weight: 70,
    is_active: false,
  },
  {
    id: 'R003',
    name: 'Data Exfiltration',
    tactic: 'TA0010',
    technique: 'T1041',
    definition: {
      time_window_seconds: 900,
      interval_seconds: 120,
      threshold: 1,
      source_types: ['firewall', 'web_proxy'],
      params: {
        multiplier_threshold: 10,
        min_volume_mb: 10,
        baseline_days: 30,
      },
    },
    confidence_weight: 90,
    is_active: false,
  },
  {
    id: 'R004',
    name: 'Log Clearing Attempt',
    tactic: 'TA0005',
    technique: 'T1070',
    definition: {
      time_window_seconds: 300,
      interval_seconds: 120,
      threshold: 1,
      source_types: ['windows_security', 'linux_auth', 'syslog'],
      params: {
        volume_drop_threshold_pct: 10,
        volume_baseline_hours: 24,
      },
      trigger_playbook: 'isolate_endpoint',
      playbook_mode: 'CONFIRM',
    },
    confidence_weight: 95,
    is_active: false,
  },
  {
    id: 'R005',
    name: 'Network Reconnaissance (Port Scan)',
    tactic: 'TA0043',
    technique: 'T1046',
    definition: {
      time_window_seconds: 120,
      interval_seconds: 60,
      threshold: 15,
      max_time_span_seconds: 60,
      source_types: ['firewall', 'web_proxy', 'syslog'],
      actions: ['network_connect'],
      outcomes: ['success', 'failure'],
    },
    confidence_weight: 70,
    is_active: false,
  },
];

async function main() {
  const connectionString = process.env.DATABASE_URL!;
  const adapter = new PrismaPg({ connectionString });
  const prisma = new PrismaClient({ adapter });

  console.log('Seeding correlation rules...');

  for (const rule of RULES) {
    const existing = await prisma.correlationRule.findUnique({
      where: { id: rule.id },
    });

    if (existing) {
      await prisma.correlationRule.update({
        where: { id: rule.id },
        data: {
          name: rule.name,
          tactic: rule.tactic,
          technique: rule.technique,
          definition: rule.definition as any,
          confidence_weight: rule.confidence_weight,
          is_active: rule.is_active,
        },
      });
      console.log(`  UPDATED ${rule.id} — ${rule.name}`);
    } else {
      await prisma.correlationRule.create({
        data: {
          id: rule.id,
          name: rule.name,
          tactic: rule.tactic,
          technique: rule.technique,
          definition: rule.definition as any,
          confidence_weight: rule.confidence_weight,
          is_active: rule.is_active,
        },
      });
      console.log(`  CREATED ${rule.id} — ${rule.name}`);
    }
  }

  await prisma.$disconnect();
  console.log(
    '\nDone. All 5 rules seeded (set to inactive — activate via API).',
  );
}

main().catch((e) => {
  console.error('Seed failed:', e);
  process.exit(1);
});
