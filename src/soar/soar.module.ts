import { Module, Logger } from '@nestjs/common';
import { SoarController } from './soar.controller';
import { SoarService } from './soar.service';
import { PfSenseAgentService } from './agents/pfsense-agent.service';
import { FortiGateAgentService } from './agents/fortigate-agent.service';
import { WindowsDefenderAgentClientService } from './agents/windows-defender-agent.service';
import { DryRunAgentService } from './agents/dry-run-agent.service';
import {
  FIREWALL_AGENT,
  IFirewallAgent,
} from './agents/firewall-agent.interface';

const firewallAgentProvider = {
  provide: FIREWALL_AGENT,
  useFactory: (
    wd: WindowsDefenderAgentClientService,
    pf: PfSenseAgentService,
    fg: FortiGateAgentService,
    dryRun: DryRunAgentService,
  ): IFirewallAgent => {
    const provider = (
      process.env.SOAR_FIREWALL_PROVIDER || 'windows_defender'
    ).toLowerCase();
    const logger = new Logger('FirewallAgentFactory');

    let agent: IFirewallAgent;
    switch (provider) {
      case 'pfsense':
        agent = pf;
        break;
      case 'fortigate':
        agent = fg;
        break;
      case 'windows_defender':
        agent = wd;
        break;
      case 'dry_run':
        agent = dryRun;
        break;
      default:
        throw new Error(
          `Unknown SOAR_FIREWALL_PROVIDER: "${provider}". ` +
            `Valid values: "pfsense", "fortigate", "windows_defender", "dry_run".`,
        );
    }

    logger.log(
      `Active firewall provider: ${agent.provider} ` +
        `(configured: ${agent.isConfigured})`,
    );

    if (!agent.isConfigured) {
      logger.warn(
        `Firewall provider "${agent.provider}" is NOT configured. ` +
          `Operations will run in dry-run / error mode until the required ` +
          `environment variables are set.`,
      );
    }

    return agent;
  },
  inject: [
    WindowsDefenderAgentClientService,
    PfSenseAgentService,
    FortiGateAgentService,
    DryRunAgentService,
  ],
};

@Module({
  controllers: [SoarController],
  providers: [
    SoarService,
    PfSenseAgentService,
    FortiGateAgentService,
    WindowsDefenderAgentClientService,
    DryRunAgentService,
    firewallAgentProvider,
  ],
  exports: [SoarService],
})
export class SoarModule {}
