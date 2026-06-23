import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';
import * as crypto from 'node:crypto';

async function main() {
  const name = process.argv[2] || 'default-collector';
  const rawKey = `siem_${crypto.randomBytes(32).toString('hex')}`;
  const keyPrefix = rawKey.substring(0, 8);
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

  const connectionString = process.env.DATABASE_URL!;
  const adapter = new PrismaPg({ connectionString });
  const prisma = new PrismaClient({ adapter });

  await prisma.apiKey.create({
    data: { name, key_hash: keyHash, key_prefix: keyPrefix },
  });

  await prisma.$disconnect();

  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║        NEW API KEY GENERATED                    ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log(`║  Name:   ${name.padEnd(36)}║`);
  console.log('║                                                  ║');
  console.log(`║  Key:    ${rawKey}  ║`);
  console.log('║                                                  ║');
  console.log('║  This is the ONLY time the raw key is shown.     ║');
  console.log('║  Store it securely.                              ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
}

main().catch((e) => {
  console.error('Failed to generate API key:', e);
  process.exit(1);
});
