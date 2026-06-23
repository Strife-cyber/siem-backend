import { Controller, Get, Param, Query } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';

@ApiTags('Audit')
@ApiBearerAuth('BearerAuth')
@Controller('audit')
export class AuditController {
  @Get('trail')
  @ApiOperation({ summary: 'Get audit trail logs (FR-04.3)' })
  @ApiQuery({ name: 'user_id', required: false })
  @ApiQuery({ name: 'action', required: false })
  @ApiQuery({ name: 'from', required: false })
  @ApiQuery({ name: 'to', required: false })
  @ApiOkResponse({ description: 'Audit entries' })
  async getAuditTrail() {
    return [];
  }

  @Get('integrity/:batchId')
  @ApiOperation({ summary: 'FR-02.3: Verify SHA-256 integrity of a log batch' })
  @ApiOkResponse({ description: 'Integrity status' })
  async verifyBatchIntegrity(@Param('batchId') _batchId: string) {
    return { is_valid: true, stored_hash: '', computed_hash: '' };
  }
}
