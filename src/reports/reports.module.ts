import { Module, OnModuleInit, Logger } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { ReportsController } from './reports.controller';
import { ReportsService } from './reports.service';
import { ReportGeneratorService } from './report-generator.service';
import { ReportsProcessor } from './reports.processor';
import { DashboardModule } from '../dashboard/dashboard.module';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'reports',
    }),
    DashboardModule,
  ],
  controllers: [ReportsController],
  providers: [ReportsService, ReportGeneratorService, ReportsProcessor],
  exports: [ReportsService],
})
export class ReportsModule implements OnModuleInit {
  private readonly logger = new Logger(ReportsModule.name);

  constructor(
    @InjectQueue('reports')
    private readonly reportsQueue: Queue,
  ) {}

  async onModuleInit() {
    await this.reportsQueue
      .removeJobScheduler('reports-cleanup')
      .catch(() => {});
    await this.reportsQueue.upsertJobScheduler(
      'reports-cleanup',
      { pattern: '0 3 * * *' },
      { name: 'cleanup', data: {} },
    );
    this.logger.log('Report cleanup scheduled (3:00 AM daily)');
  }
}
