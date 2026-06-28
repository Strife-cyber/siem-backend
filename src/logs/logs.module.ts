import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { LogsService } from './logs.service';
import { LogsController } from './logs.controller';
import { LogsProcessor } from './processors/logs.processor';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'logs',
    }),
    BullModule.registerQueue({
      name: 'ueba',
    }),
  ],
  controllers: [LogsController],
  providers: [LogsService, LogsProcessor],
})
export class LogsModule {}
