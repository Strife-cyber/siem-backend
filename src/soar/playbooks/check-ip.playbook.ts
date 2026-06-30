import { Logger } from '@nestjs/common';
import type { PfSenseClientService, PfSenseRule } from '../pfsense-client.service';

export async function checkIpPlaybook(
  pfsense: PfSenseClientService,
  ip: string,
  logger: Logger,
): Promise<{ blocked: boolean; rules: PfSenseRule[] }> {
  try {
    const result = await pfsense.checkIP(ip);
    if (result.status === 'ok') {
      const data = result.data!;
      if (data.blocked) {
        logger.warn(`[check_ip] ${ip} is BLOCKED by ${data.rules.length} rule(s)`);
      } else {
        logger.log(`[check_ip] ${ip} is NOT blocked`);
      }
      return data;
    }
    logger.error(`[check_ip] Failed: ${result.message}`);
    return { blocked: false, rules: [] };
  } catch (err: any) {
    logger.error(`[check_ip] Error: ${err.message}`);
    return { blocked: false, rules: [] };
  }
}
