import { Logger } from '@nestjs/common';
import type { PfSenseClientService } from '../pfsense-client.service';

export async function isolateHostPlaybook(
  pfsense: PfSenseClientService,
  hosts: string[],
  reason: string,
  logger: Logger,
): Promise<{ isolated: string[]; failed: string[] }> {
  const isolated: string[] = [];
  const failed: string[] = [];

  for (const host of hosts) {
    try {
      const result = await pfsense.isolateHost(host, reason);
      if (result.status === 'ok') {
        isolated.push(host);
        logger.warn(
          `[isolate_host] Isolated ${host}: inbound=${(result.data as any)?.inboundId}, outbound=${(result.data as any)?.outboundId}`,
        );
      } else {
        failed.push(host);
        logger.error(`[isolate_host] Failed to isolate ${host}: ${result.message}`);
      }
    } catch (err: any) {
      failed.push(host);
      logger.error(`[isolate_host] Error isolating ${host}: ${err.message}`);
    }
  }

  return { isolated, failed };
}
