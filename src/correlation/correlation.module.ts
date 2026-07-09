import { Module, OnModuleInit, Logger } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { CorrelationService } from './correlation.service';
import { CorrelationScheduler } from './correlation.scheduler';
import { SoarModule } from '../soar/soar.module';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'correlation',
    }),
    BullModule.registerQueue({
      name: 'notifications',
    }),
    BullModule.registerQueue({
      name: 'logs',
    }),
    BullModule.registerQueue({
      name: 'ueba',
    }),
    BullModule.registerQueue({
      name: 'reports',
    }),
    SoarModule,
  ],
  providers: [CorrelationService, CorrelationScheduler],
})
export class CorrelationModule implements OnModuleInit {
  private readonly logger = new Logger(CorrelationModule.name);

  constructor(
    @InjectQueue('correlation')
    private readonly correlationQueue: Queue,
  ) {}

  async onModuleInit() {
    // Remove any existing job scheduler to avoid duplicates
    await this.correlationQueue
      .removeJobScheduler('correlation-cycle')
      .catch(() => {});
    // Add a repeatable job that runs every 60 seconds
    await this.correlationQueue.upsertJobScheduler(
      'correlation-cycle',
      { every: 60_000 },
      {
        name: 'cycle',
        data: undefined,
      },
    );
    this.logger.log('Correlation engine scheduled: running every 60s');
  }
}
