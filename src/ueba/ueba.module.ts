import { Module, OnModuleInit, Logger } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { UebaController } from './ueba.controller';
import { UebaService } from './ueba.service';
import { UebaBaselineService } from './ueba-baseline.service';
import { UebaScorerService } from './ueba-scorer.service';
import { UebaProcessor } from './ueba.processor';
import { SoarModule } from '../soar/soar.module';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'ueba',
    }),
    SoarModule,
  ],
  controllers: [UebaController],
  providers: [
    UebaService,
    UebaBaselineService,
    UebaScorerService,
    UebaProcessor,
  ],
  exports: [UebaService, UebaScorerService],
})
export class UebaModule implements OnModuleInit {
  private readonly logger = new Logger(UebaModule.name);

  constructor(
    @InjectQueue('ueba')
    private readonly uebaQueue: Queue,
  ) {}

  async onModuleInit() {
    // Schedule nightly baseline rebuild at 2:00 AM every day
    await this.uebaQueue
      .removeJobScheduler('ueba-nightly-baseline')
      .catch(() => {});
    await this.uebaQueue.upsertJobScheduler(
      'ueba-nightly-baseline',
      { pattern: '0 2 * * *' },
      {
        name: 'rebuild-baselines',
        data: {},
      },
    );
    this.logger.log('UEBA nightly baseline rebuild scheduled (2:00 AM daily)');
  }
}
