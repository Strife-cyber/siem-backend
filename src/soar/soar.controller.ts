import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  Inject,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { FIREWALL_AGENT } from './agents/firewall-agent.interface';
import type { IFirewallAgent } from './agents/firewall-agent.interface';
import { SoarService } from './soar.service';
import { PfSenseAgentService } from './agents/pfsense-agent.service';
import {
  PlaybookExecutionDto,
  AbortPlaybookDto,
  DirectBlockIpDto,
  DirectBlockPortDto,
  DirectTempBlockDto,
  DirectAliasDto,
  UnblockIpDto,
} from './dto/soar.dto';
import { blockIpPlaybook } from './playbooks/block-ip.playbook';
import { blockPortPlaybook } from './playbooks/block-port.playbook';
import { temporaryBlockPlaybook } from './playbooks/temporary-block.playbook';
import { checkIpPlaybook } from './playbooks/check-ip.playbook';
import {
  createAliasPlaybook,
  deleteAliasPlaybook,
} from './playbooks/aliases.playbook';
import { Logger } from '@nestjs/common';

@ApiTags('SOAR')
@ApiBearerAuth('BearerAuth')
@Controller('soar')
export class SoarController {
  private readonly logger = new Logger(SoarController.name);

  constructor(
    private readonly soarService: SoarService,
    @Inject(FIREWALL_AGENT) private readonly agent: IFirewallAgent,
  ) {}

  // ══════════════════════════════════════════════════
  //  Playbook execution
  // ══════════════════════════════════════════════════

  @Post('execute')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Execute a SOAR playbook from an incident' })
  @ApiCreatedResponse({ description: 'Playbook queued' })
  async executePlaybook(@Body() dto: PlaybookExecutionDto) {
    return this.soarService.executePlaybook(dto);
  }

  @Post('abort')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Abort a pending playbook execution' })
  @ApiOkResponse({ description: 'Aborted successfully' })
  async abortPlaybook(@Body() dto: AbortPlaybookDto) {
    return this.soarService.abortPlaybook(dto.execution_id);
  }

  // ══════════════════════════════════════════════════
  //  Direct firewall actions (provider-agnostic)
  // ══════════════════════════════════════════════════

  @Post('block-ip')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Block an IP address on the active firewall' })
  async directBlockIp(@Body() dto: DirectBlockIpDto) {
    const result = await blockIpPlaybook(
      this.agent,
      [dto.ip],
      dto.reason ?? 'Manual block',
      this.logger,
    );
    return result;
  }

  @Post('block-port')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Block a specific port from an IP on the active firewall' })
  async directBlockPort(@Body() dto: DirectBlockPortDto) {
    const result = await blockPortPlaybook(
      this.agent,
      [{ ip: dto.ip, port: dto.port, protocol: dto.protocol }],
      dto.reason ?? 'Manual port block',
      this.logger,
    );
    return result;
  }

  @Post('temporary-block')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Temporarily block an IP for a given duration' })
  async directTempBlock(@Body() dto: DirectTempBlockDto) {
    const result = await temporaryBlockPlaybook(
      this.agent,
      undefined,
      [dto.ip],
      dto.reason ?? 'Temporary manual block',
      dto.ttl_seconds,
      '00000000-0000-0000-0000-000000000000',
      this.logger,
    );
    return result;
  }

  @Get('check-ip/:ip')
  @ApiOperation({ summary: 'Check if an IP is blocked on the active firewall' })
  async directCheckIp(@Param('ip') ip: string) {
    return checkIpPlaybook(this.agent, ip, this.logger);
  }

  @Post('unblock-ip')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Unblock an IP address on the active firewall' })
  async unblockIp(@Body() dto: UnblockIpDto) {
    return this.agent.unblockIp(dto.ip);
  }

  @Get('rules')
  @ApiOperation({ summary: 'List all firewall rules managed by Smart SIEM' })
  async listRules() {
    return this.agent.listRules();
  }

  @Delete('rule/:name')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Delete a specific firewall rule by its name' })
  async deleteRule(@Param('name') name: string) {
    return this.agent.deleteRule(name);
  }

  @Get('health')
  @ApiOperation({ summary: 'Get the active firewall provider health status' })
  async healthCheck() {
    return this.agent.healthCheck();
  }

  // ══════════════════════════════════════════════════
  //  CONFIRM mode — analyst approval
  // ══════════════════════════════════════════════════

  @Get('pending')
  @ApiOperation({
    summary: 'List all playbook executions pending analyst approval (CONFIRM mode)',
  })
  async getPendingExecutions() {
    return this.soarService.getPendingExecutions();
  }

  @Post('approve/:executionId')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Approve a CONFIRM-mode playbook execution' })
  async approveExecution(@Param('executionId') executionId: string) {
    return this.soarService.approveExecution(executionId);
  }

  // ══════════════════════════════════════════════════
  //  Direct firewall actions (pfSense-specific)
  // ══════════════════════════════════════════════════

  @Post('aliases')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Create an IP alias on pfSense (pfSense only)' })
  async createAlias(@Body() dto: DirectAliasDto) {
    this.ensurePfSense('create aliases');
    const pfsense = this.agent as unknown as PfSenseAgentService;
    return createAliasPlaybook(
      pfsense,
      dto.name,
      dto.addresses,
      dto.description ?? 'Smart SIEM alias',
      this.logger,
    );
  }

  @Post('aliases/:id/delete')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Delete an IP alias from pfSense by its ID (pfSense only)' })
  async deleteAlias(@Param('id') id: string) {
    this.ensurePfSense('delete aliases');
    const pfsense = this.agent as unknown as PfSenseAgentService;
    return deleteAliasPlaybook(pfsense, id, this.logger);
  }

  @Get('aliases')
  @ApiOperation({ summary: 'List all aliases from pfSense (pfSense only)' })
  async listAliases() {
    this.ensurePfSense('list aliases');
    const pfsense = this.agent as unknown as PfSenseAgentService;
    const result = await pfsense.listAliases();
    return result.data ?? [];
  }

  // ══════════════════════════════════════════════════
  //  Status (provider-agnostic, alias of health)
  // ══════════════════════════════════════════════════

  @Get('status')
  @ApiOperation({ summary: 'Get the active firewall provider status' })
  @ApiOkResponse({
    description: 'Firewall provider status with version, rules count, etc.',
  })
  async getStatus() {
    return this.agent.healthCheck();
  }

  // ══════════════════════════════════════════════════
  //  Helpers
  // ══════════════════════════════════════════════════

  private ensurePfSense(operation: string): void {
    if (this.agent.provider !== 'pfsense') {
      throw new BadRequestException(
        `Cannot ${operation}: this operation requires the pfSense firewall provider. ` +
          `Current provider: ${this.agent.provider}. ` +
          `Set SOAR_FIREWALL_PROVIDER=pfsense in your environment.`,
      );
    }
  }
}
