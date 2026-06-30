import { Logger } from '@nestjs/common';
import type { PfSenseClientService } from '../pfsense-client.service';

export async function createAliasPlaybook(
  pfsense: PfSenseClientService,
  name: string,
  ips: string[],
  description: string,
  logger: Logger,
): Promise<{ success: boolean; name: string }> {
  try {
    const result = await pfsense.createAlias(name, ips, description);
    if (result.status === 'ok') {
      logger.warn(`[create_alias] Created alias "${name}" with ${ips.length} IPs`);
      return { success: true, name };
    }
    logger.error(`[create_alias] Failed: ${result.message}`);
    return { success: false, name };
  } catch (err: any) {
    logger.error(`[create_alias] Error: ${err.message}`);
    return { success: false, name };
  }
}

export async function deleteAliasPlaybook(
  pfsense: PfSenseClientService,
  name: string,
  logger: Logger,
): Promise<{ success: boolean; name: string }> {
  try {
    const result = await pfsense.deleteAlias(name);
    if (result.status === 'ok') {
      logger.warn(`[delete_alias] Deleted alias "${name}"`);
      return { success: true, name };
    }
    logger.error(`[delete_alias] Failed: ${result.message}`);
    return { success: false, name };
  } catch (err: any) {
    logger.error(`[delete_alias] Error: ${err.message}`);
    return { success: false, name };
  }
}
