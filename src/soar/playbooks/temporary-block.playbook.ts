import { Logger } from '@nestjs/common';
import type { PfSenseClientService } from '../pfsense-client.service';
import type { PrismaService } from '../../prisma/prisma.service';

export async function temporaryBlockPlaybook(
  pfsense: PfSenseClientService,
  prisma: PrismaService | undefined,
  ips: string[],
  reason: string,
  ttlSeconds: number,
  incidentId: string,
  logger: Logger,
): Promise<{ blocked: string[]; failed: string[]; cleanupJobId?: string }> {
  const blocked: string[] = [];
  const failed: string[] = [];

  for (const ip of ips) {
    try {
      const result = await pfsense.blockIP(ip, `[TEMP] ${reason}`);
      if (result.status === 'ok') {
        blocked.push(ip);
        const ruleId = (result.data as any)?.id;
        logger.warn(
          `[temporary_block] Blocked ${ip} for ${ttlSeconds}s (rule: ${ruleId})`,
        );

        // Create a future playbook execution to remove the block
        if (prisma) {
          await prisma.playbookExecution.create({
            data: {
              incident_id: incidentId,
              playbook_name: 'remove_rule',
              mode: 'AUTO',
              status: 'PENDING',
              result_payload: {
                pfSenseRuleId: ruleId,
                ip,
                scheduledFor: new Date(
                  Date.now() + ttlSeconds * 1000,
                ).toISOString(),
              } as any,
            } as any,
          });
          logger.log(
            `[temporary_block] Cleanup scheduled for ${new Date(Date.now() + ttlSeconds * 1000).toISOString()}`,
          );
        }
      } else {
        failed.push(ip);
        logger.error(
          `[temporary_block] Failed to block ${ip}: ${result.message}`,
        );
      }
    } catch (err: any) {
      failed.push(ip);
      logger.error(`[temporary_block] Error blocking ${ip}: ${err.message}`);
    }
  }

  return { blocked, failed };
}
