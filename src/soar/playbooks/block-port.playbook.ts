import { Logger } from '@nestjs/common';
import type { PfSenseClientService } from '../pfsense-client.service';

export interface PortBlockTarget {
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
}

export async function blockPortPlaybook(
  pfsense: PfSenseClientService,
  targets: PortBlockTarget[],
  reason: string,
  logger: Logger,
): Promise<{ blocked: PortBlockTarget[]; failed: PortBlockTarget[] }> {
  const blocked: PortBlockTarget[] = [];
  const failed: PortBlockTarget[] = [];

  for (const target of targets) {
    try {
      const result = await pfsense.blockPort(
        target.ip,
        target.port,
        target.protocol,
        reason,
      );
      if (result.status === 'ok') {
        blocked.push(target);
        logger.warn(
          `[block_port] Blocked ${target.ip}:${target.port}/${target.protocol}: ${reason}`,
        );
      } else {
        failed.push(target);
        logger.error(
          `[block_port] Failed to block ${target.ip}:${target.port}: ${result.message}`,
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
