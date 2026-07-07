import { Logger } from '@nestjs/common';
import type { IFirewallAgent } from '../agents/firewall-agent.interface';
import type { CheckIpResponse } from '../agents/firewall-agent.interface';

export async function checkIpPlaybook(
  agent: IFirewallAgent,
  ip: string,
  logger: Logger,
): Promise<CheckIpResponse> {
  try {
    const result = await agent.checkIp(ip);
    if (result.blocked) {
      logger.warn(
        `[check_ip] ${ip} is BLOCKED by ${result.rules.length} rule(s)`,
      );
    } else {
      logger.log(`[check_ip] ${ip} is NOT blocked`);
    }
    return result;
  } catch (err: any) {
    logger.error(`[check_ip] Error: ${err.message}`);
    return { blocked: false, rules: [] };
  }
}
