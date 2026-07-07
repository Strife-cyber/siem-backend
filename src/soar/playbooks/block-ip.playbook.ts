import { Logger } from '@nestjs/common';
import type { IFirewallAgent } from '../agents/firewall-agent.interface';

export async function blockIpPlaybook(
  agent: IFirewallAgent,
  ips: string[],
  reason: string,
  logger: Logger,
): Promise<{ blocked: string[]; failed: string[] }> {
  const blocked: string[] = [];
  const failed: string[] = [];

  for (const ip of ips) {
    try {
      const result = await agent.blockIp(ip, reason);
      if (result.success) {
        blocked.push(ip);
        logger.warn(`[block_ip] Blocked ${ip}: ${reason}`);
      } else {
        failed.push(ip);
        logger.error(`[block_ip] Failed to block ${ip}`);
      }
    } catch (err: any) {
      failed.push(ip);
      logger.error(`[block_ip] Error blocking ${ip}: ${err.message}`);
    }
  }

  return { blocked, failed };
}
