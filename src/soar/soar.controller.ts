import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { SoarService } from './soar.service';
import { PfSenseClientService } from './pfsense-client.service';
import {
  PlaybookExecutionDto,
  AbortPlaybookDto,
  DirectBlockIpDto,
  DirectBlockPortDto,
  DirectTempBlockDto,
  DirectAliasDto,
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
    private readonly pfsense: PfSenseClientService,
  ) {}

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

  @Post('block-ip')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Directly block an IP on pfSense' })
  async directBlockIp(@Body() dto: DirectBlockIpDto) {
    const result = await blockIpPlaybook(
      this.pfsense,
      [dto.ip],
      dto.reason ?? 'Manual block',
      this.logger,
    );
    return result;
  }

  @Post('block-port')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Block a specific port from an IP on pfSense' })
  async directBlockPort(@Body() dto: DirectBlockPortDto) {
    const result = await blockPortPlaybook(
      this.pfsense,
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
      this.pfsense,
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
  @ApiOperation({ summary: 'Check if an IP is blocked on pfSense' })
  async directCheckIp(@Param('ip') ip: string) {
    return checkIpPlaybook(this.pfsense, ip, this.logger);
  }

  @Post('aliases')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Create an IP alias on pfSense' })
  async createAlias(@Body() dto: DirectAliasDto) {
    return createAliasPlaybook(
      this.pfsense,
      dto.name,
      dto.addresses,
      dto.description ?? 'Smart SIEM alias',
      this.logger,
    );
  }

  @Post('aliases/:id/delete')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Delete an IP alias from pfSense by its ID' })
  async deleteAlias(@Param('id') id: string) {
    return deleteAliasPlaybook(this.pfsense, id, this.logger);
  }

  @Get('aliases')
  @ApiOperation({ summary: 'List all aliases from pfSense' })
  async listAliases() {
    const result = await this.pfsense.listAliases();
    return result.data ?? [];
  }

  @Get('status')
  @ApiOperation({ summary: 'Get pfSense connection status and stats' })
  @ApiOkResponse({
    description: 'pfSense status with version, rules count, aliases count',
  })
  async getStatus() {
    return this.pfsense.getStatus();
  }
}
