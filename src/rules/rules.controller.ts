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
import { RulesService } from './rules.service';
import { CreateCorrelationRuleDto } from './dto/correlation-rule.dto';

@ApiTags('Rules')
@ApiBearerAuth('BearerAuth')
@Controller('rules')
export class RulesController {
  constructor(private readonly rulesService: RulesService) {}

  @Get()
  @ApiOperation({ summary: 'List all correlation rules (FR-03.1)' })
  @ApiOkResponse({ description: 'List of rules' })
  async listRules() {
    return this.rulesService.findAll();
  }

  @Post()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Create a new correlation rule (ADMIN only)' })
  @ApiCreatedResponse({ description: 'Rule created' })
  async createRule(@Body() dto: CreateCorrelationRuleDto) {
    return this.rulesService.create(dto);
  }

  @Get(':ruleId')
  @ApiOperation({ summary: 'Get a specific rule' })
  @ApiOkResponse({ description: 'Rule found' })
  async getRule(@Param('ruleId') ruleId: string) {
    return this.rulesService.findOne(ruleId);
  }

  @Put(':ruleId')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Update an existing rule (ADMIN only)' })
  @ApiOkResponse({ description: 'Updated' })
  async updateRule(
    @Param('ruleId') ruleId: string,
    @Body() dto: CreateCorrelationRuleDto,
  ) {
    return this.rulesService.update(ruleId, dto);
  }

  @Delete(':ruleId')
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Deactivate/Delete a rule (ADMIN only)' })
  @ApiOkResponse({ description: 'Deleted successfully' })
  async deleteRule(@Param('ruleId') ruleId: string) {
    await this.rulesService.remove(ruleId);
  }
}
