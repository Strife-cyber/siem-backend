import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Body,
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
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../../generated/prisma/enums';
import { CreateCorrelationRuleDto } from './dto/correlation-rule.dto';

@ApiTags('Rules')
@ApiBearerAuth('BearerAuth')
@Controller('rules')
export class RulesController {
  @Get()
  @ApiOperation({ summary: 'List all correlation rules (FR-03.1)' })
  @ApiOkResponse({ description: 'List of rules' })
  listRules() {
    return [];
  }

  @Post()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Create a new correlation rule (ADMIN only)' })
  @ApiCreatedResponse({ description: 'Rule created' })
  createRule(@Body() _dto: CreateCorrelationRuleDto) {
    return {};
  }

  @Get(':ruleId')
  @ApiOperation({ summary: 'Get a specific rule' })
  @ApiOkResponse({ description: 'Rule found' })
  getRule(@Param('ruleId') _ruleId: string) {
    return {};
  }

  @Put(':ruleId')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Update an existing rule (ADMIN only)' })
  @ApiOkResponse({ description: 'Updated' })
  updateRule(
    @Param('ruleId') _ruleId: string,
    @Body() _dto: CreateCorrelationRuleDto,
  ) {
    return {};
  }

  @Delete(':ruleId')
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Deactivate/Delete a rule (ADMIN only)' })
  @ApiOkResponse({ description: 'Deleted successfully' })
  deleteRule(@Param('ruleId') _ruleId: string) {
    return;
  }
}
