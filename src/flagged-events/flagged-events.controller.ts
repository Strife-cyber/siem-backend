import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiOkResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';
import { FlaggedEventsService } from './flagged-events.service';
import { FlagEventDto } from './dto/flag-event.dto';
import { UpdateFlagDto } from './dto/update-flag.dto';
import { ListFlagsDto } from './dto/list-flags.dto';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('Flagged Events')
@ApiBearerAuth('BearerAuth')
@UseGuards(JwtAuthGuard)
@Controller('logs/flagged')
export class FlaggedEventsController {
  constructor(private readonly flaggedEventsService: FlaggedEventsService) {}

  @Post()
  @ApiOperation({
    summary: 'Flag a log event for cross-investigation (FR-06.3)',
  })
  @ApiCreatedResponse({ description: 'Event flagged successfully' })
  async flag(
    @Body() dto: FlagEventDto,
    @CurrentUser('sub') userId: string,
  ) {
    return this.flaggedEventsService.flag(dto, userId);
  }

  @Get()
  @ApiOperation({ summary: 'List all flagged events with filters' })
  @ApiOkResponse({ description: 'Paginated list of flagged events' })
  async list(@Query() dto: ListFlagsDto) {
    return this.flaggedEventsService.list(dto);
  }

  @Patch(':ingestionHash')
  @ApiOperation({
    summary: 'Update a flag (status, reason, investigation group)',
  })
  @ApiOkResponse({ description: 'Flag updated' })
  async update(
    @Param('ingestionHash') ingestionHash: string,
    @Body() dto: UpdateFlagDto,
  ) {
    return this.flaggedEventsService.update(ingestionHash, dto);
  }

  @Delete(':ingestionHash')
  @ApiOperation({ summary: 'Remove a flag from an event' })
  @ApiOkResponse({ description: 'Flag removed' })
  async unflag(@Param('ingestionHash') ingestionHash: string) {
    await this.flaggedEventsService.unflag(ingestionHash);
    return { success: true };
  }

  @Post(':fromHash/link/:toHash')
  @ApiOperation({
    summary: 'Link two flagged events together for cross-investigation',
  })
  @ApiCreatedResponse({ description: 'Events linked' })
  async link(
    @Param('fromHash') fromHash: string,
    @Param('toHash') toHash: string,
    @CurrentUser('sub') userId: string,
  ) {
    await this.flaggedEventsService.link(fromHash, toHash, userId);
    return { success: true };
  }
}
