import { Logger } from '@nestjs/common';
import type { PfSenseClientService } from '../pfsense-client.service';

export async function blockIpPlaybook(
  pfsense: PfSenseClientService,
  ips: string[],
  reason: string,
  logger: Logger,
): Promise<{ blocked: string[]; failed: string[] }> {
  const blocked: string[] = [];
  const failed: string[] = [];

  for (const ip of ips) {
    try {
      const result = await pfsense.blockIP(ip, reason);
      if (result.status === 'ok') {
        blocked.push(ip);
        logger.warn(`[block_ip] Blocked ${ip}: ${reason}`);
      } else {
        failed.push(ip);
        logger.error(`[block_ip] Failed to block ${ip}: ${result.message}`);
      }
    } catch (err: any) {
      failed.push(ip);
      logger.error(`[block_ip] Error blocking ${ip}: ${err.message}`);
    }
  }

  return { blocked, failed };
}
