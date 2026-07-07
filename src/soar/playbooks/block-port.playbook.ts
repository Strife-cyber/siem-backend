import { Logger } from '@nestjs/common';
import type { IFirewallAgent } from '../agents/firewall-agent.interface';

export interface PortBlockTarget {
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
}

export async function blockPortPlaybook(
  agent: IFirewallAgent,
  targets: PortBlockTarget[],
  reason: string,
  logger: Logger,
): Promise<{ blocked: PortBlockTarget[]; failed: PortBlockTarget[] }> {
  const blocked: PortBlockTarget[] = [];
  const failed: PortBlockTarget[] = [];

  for (const target of targets) {
    try {
      const result = await agent.blockPort(
        target.ip,
        target.port,
        target.protocol,
        reason,
      );
      if (result.success) {
        blocked.push(target);
        logger.warn(
          `[block_port] Blocked ${target.ip}:${target.port}/${target.protocol}: ${reason}`,
        );
      } else {
        failed.push(target);
        logger.error(
          `[block_port] Failed to block ${target.ip}:${target.port}`,
        );
      }
    } catch (err: any) {
      failed.push(target);
      logger.error(
        `[block_port] Error blocking ${target.ip}:${target.port}: ${err.message}`,
      );
    }
  }

  return { blocked, failed };
}
