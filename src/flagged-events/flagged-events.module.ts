import { Module } from '@nestjs/common';
import { FlaggedEventsService } from './flagged-events.service';
import { FlaggedEventsController } from './flagged-events.controller';

@Module({
  controllers: [FlaggedEventsController],
  providers: [FlaggedEventsService],
})
export class FlaggedEventsModule {}
