import { Controller, Get, Param, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { AuditService } from './audit.service';

@ApiTags('Audit')
@ApiBearerAuth('BearerAuth')
@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get('trail')
  @ApiOperation({ summary: 'Get audit trail logs (FR-04.3)' })
  @ApiQuery({ name: 'user_id', required: false })
  @ApiQuery({ name: 'action', required: false })
  @ApiQuery({ name: 'from', required: false })
  @ApiQuery({ name: 'to', required: false })
  @ApiOkResponse({ description: 'Audit entries' })
  async getAuditTrail(
    @Query('user_id') userId?: string,
    @Query('action') action?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    return this.auditService.getTrail({ user_id: userId, action, from, to });
  }

  @Get('integrity/:batchId')
  @ApiOperation({ summary: 'FR-02.3: Verify SHA-256 integrity of a log batch' })
  @ApiOkResponse({ description: 'Integrity status' })
  async verifyBatchIntegrity(@Param('batchId') batchId: string) {
    return this.auditService.verifyBatchIntegrity(batchId);
  }
}
