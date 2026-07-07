import { Logger } from '@nestjs/common';
import type { IFirewallAgent } from '../agents/firewall-agent.interface';
import type { PrismaService } from '../../prisma/prisma.service';

export async function temporaryBlockPlaybook(
  agent: IFirewallAgent,
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
      const result = await agent.blockIp(ip, `[TEMP] ${reason}`);
      if (result.success) {
        blocked.push(ip);
        const ruleName = result.rule_name as string | undefined;
        logger.warn(
          `[temporary_block] Blocked ${ip} for ${ttlSeconds}s (rule: ${ruleName ?? 'unknown'})`,
        );

        // Create a future playbook execution to remove the block
        if (prisma) {
          const cleanupExecution = await prisma.playbookExecution.create({
            data: {
              incident_id: incidentId,
              playbook_name: 'remove_rule',
              mode: 'AUTO',
              status: 'PENDING',
              result_payload: {
                ip,
                ruleName,
                scheduledFor: new Date(
                  Date.now() + ttlSeconds * 1000,
                ).toISOString(),
              } as any,
            } as any,
          });
          logger.log(
            `[temporary_block] Cleanup scheduled for ${new Date(Date.now() + ttlSeconds * 1000).toISOString()} (execution: ${cleanupExecution.id})`,
          );
        }
      } else {
        failed.push(ip);
        logger.error(
          `[temporary_block] Failed to block ${ip}: provider returned error`,
        );
      }
    } catch (err: any) {
      failed.push(ip);
      logger.error(`[temporary_block] Error blocking ${ip}: ${err.message}`);
    }
  }

  return { blocked, failed };
}
