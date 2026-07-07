import { Logger } from '@nestjs/common';
import type { IFirewallAgent } from '../agents/firewall-agent.interface';

export async function isolateHostPlaybook(
  agent: IFirewallAgent,
  hosts: string[],
  reason: string,
  logger: Logger,
): Promise<{ isolated: string[]; failed: string[] }> {
  const isolated: string[] = [];
  const failed: string[] = [];

  for (const host of hosts) {
    try {
      const result = await agent.isolateHost(host, reason);
      if (result.success) {
        isolated.push(host);
        logger.warn(`[isolate_host] Isolated ${host}`);
      } else {
        failed.push(host);
        logger.error(`[isolate_host] Failed to isolate ${host}`);
      }
    } catch (err: any) {
      failed.push(host);
      logger.error(`[isolate_host] Error isolating ${host}: ${err.message}`);
    }
  }

  return { isolated, failed };
}
