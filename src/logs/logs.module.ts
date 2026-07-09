import { Module, OnModuleInit, Logger } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { LogsService } from './logs.service';
import { LogsController } from './logs.controller';
import { LogsProcessor } from './processors/logs.processor';
import { LogsRetentionService } from './logs-retention.service';

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
  providers: [
    LogsService,
    LogsProcessor,
    LogsRetentionService,
  ],
})
export class LogsModule implements OnModuleInit {
  private readonly logger = new Logger(LogsModule.name);

  constructor(
    @InjectQueue('logs')
    private readonly logsQueue: Queue,
  ) {}

  async onModuleInit() {
    // Run daily at 02:30 UTC: archive logs older than 30 days, then purge.
    await this.logsQueue.removeJobScheduler('logs-retention-archive').catch(() => {});
    await this.logsQueue.upsertJobScheduler(
      'logs-retention-archive',
      { pattern: '30 2 * * *' },
      { name: 'retention-archive', data: {} },
    );
    this.logger.log('Logs retention/archive scheduled (02:30 UTC daily)');
  }
}
