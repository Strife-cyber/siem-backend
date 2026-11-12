import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiAcceptedResponse,
} from '@nestjs/swagger';
import { SoarService } from './soar.service';
import {
  PlaybookExecutionDto,
  AbortPlaybookDto,
  DirectBlockIpDto,
  DirectBlockPortDto,
  DirectTempBlockDto,
  DirectAliasDto,
  UnblockIpDto,
} from './dto/soar.dto';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../../generated/prisma/enums';

/**
 * SOAR endpoints.
 *
 * RBAC (FR-06.3): every state-changing action (execute/approve/abort playbooks,
 * block/unblock IPs or ports, manage aliases and firewall rules) requires
 * ANALYST or ADMIN. Read-only queries (status, health, pending queue,
 * action history, IP checks) are open to any authenticated role.
 */
@ApiTags('SOAR')
@ApiBearerAuth('BearerAuth')
@Controller('soar')
export class SoarController {
  constructor(private readonly soarService: SoarService) {}

  // ══════════════════════════════════════════════════
  //  Playbook execution
  // ══════════════════════════════════════════════════

  @Post('execute')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Execute a SOAR playbook from an incident (ANALYST+)',
  })
  @ApiAcceptedResponse({ description: 'Playbook queued' })
  async executePlaybook(@Body() dto: PlaybookExecutionDto) {
    return this.soarService.executePlaybook(dto);
  }

  @Post('abort')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Abort a pending playbook execution (ANALYST+)' })
  @ApiOkResponse({ description: 'Aborted successfully' })
  async abortPlaybook(@Body() dto: AbortPlaybookDto) {
    return this.soarService.abortPlaybook(dto.execution_id);
  }

  // ══════════════════════════════════════════════════
  //  Direct firewall actions (provider-agnostic)
  // ══════════════════════════════════════════════════

  @Post('block-ip')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Block an IP address on the active firewall (ANALYST+)',
  })
  async directBlockIp(@Body() dto: DirectBlockIpDto) {
    return this.soarService.directBlockIp(dto.ip, dto.reason);
  }

  @Post('block-port')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary:
      'Block a specific port from an IP on the active firewall (ANALYST+)',
  })
  async directBlockPort(@Body() dto: DirectBlockPortDto) {
    return this.soarService.directBlockPort(
      dto.ip,
      dto.port,
      dto.protocol,
      dto.reason,
    );
  }

  @Post('temporary-block')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Temporarily block an IP for a given duration (ANALYST+)',
  })
  async directTempBlock(@Body() dto: DirectTempBlockDto) {
    return this.soarService.directTemporaryBlock(
      dto.ip,
      dto.ttl_seconds,
      dto.reason,
    );
  }

  @Get('check-ip/:ip')
  @ApiOperation({ summary: 'Check if an IP is blocked on the active firewall' })
  async directCheckIp(@Param('ip') ip: string) {
    return this.soarService.checkIp(ip);
  }

  @Post('unblock-ip')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Unblock an IP address on the active firewall (ANALYST+)',
  })
  async unblockIp(@Body() dto: UnblockIpDto) {
    return this.soarService.unblockIp(dto.ip);
  }

  @Get('rules')
  @ApiOperation({ summary: 'List all firewall rules managed by Smart SIEM' })
  async listRules() {
    return this.soarService.listFirewallRules();
  }

  @Delete('rule/:name')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete a specific firewall rule by its name (ANALYST+)',
  })
  async deleteRule(@Param('name') name: string) {
    return this.soarService.deleteFirewallRule(name);
  }

  @Get('health')
  @ApiOperation({ summary: 'Get the active firewall provider health status' })
  @ApiOkResponse({
    description: 'Firewall provider status with version, rules count, etc.',
  })
  async healthCheck() {
    return this.soarService.firewallHealth();
  }

  // ══════════════════════════════════════════════════
  //  CONFIRM mode — analyst approval
  // ══════════════════════════════════════════════════

  @Get('pending')
  @ApiOperation({
    summary:
      'List all playbook executions pending analyst approval (CONFIRM mode)',
  })
  async getPendingExecutions() {
    return this.soarService.getPendingExecutions();
  }

  @Post('approve/:executionId')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Approve a CONFIRM-mode playbook execution (ANALYST+)',
  })
  async approveExecution(@Param('executionId') executionId: string) {
    return this.soarService.approveExecution(executionId);
  }

  // ══════════════════════════════════════════════════
  //  Direct firewall actions (pfSense-specific)
  // ══════════════════════════════════════════════════

  @Post('aliases')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Create an IP alias on pfSense (pfSense only, ANALYST+)',
  })
  async createAlias(@Body() dto: DirectAliasDto) {
    return this.soarService.createAlias(
      dto.name,
      dto.addresses,
      dto.description,
    );
  }

  @Post('aliases/:id/delete')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary:
      'Delete an IP alias from pfSense by its ID (pfSense only, ANALYST+)',
  })
  async deleteAlias(@Param('id') id: string) {
    return this.soarService.deleteAlias(id);
  }

  @Get('aliases')
  @ApiOperation({ summary: 'List all aliases from pfSense (pfSense only)' })
  async listAliases() {
    return this.soarService.listAliases();
  }

  // ══════════════════════════════════════════════════
  //  Status (provider-agnostic, alias of health)
  // ══════════════════════════════════════════════════

  // ══════════════════════════════════════════════════
  //  SOAR Action tracking — undo & audit
  // ══════════════════════════════════════════════════

  @Get('actions')
  @ApiOperation({
    summary: 'List all SOAR actions (block/unblock/isolate) with undo support',
  })
  async listActions(@Query('incident_id') incidentId?: string) {
    return this.soarService.listActions(incidentId);
  }

  @Post('actions/:id/undo')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Undo a SOAR action (unblock IP or un-isolate host, ANALYST+)',
  })
  async undoAction(@Param('id') id: string) {
    return this.soarService.undoAction(id);
  }

  @Get('status')
  @ApiOperation({ summary: 'Get the active firewall provider status' })
  @ApiOkResponse({
    description: 'Firewall provider status with version, rules count, etc.',
  })
  async getStatus() {
    return this.soarService.firewallHealth();
  }
}
