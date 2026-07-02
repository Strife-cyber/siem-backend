import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { ReportsService } from './reports.service';

@Processor('reports', { concurrency: 1 })
export class ReportsProcessor extends WorkerHost {
  private readonly logger = new Logger(ReportsProcessor.name);

  constructor(private readonly reportsService: ReportsService) {
    super();
  }

  async process(job: Job): Promise<void> {
    switch (job.name) {
      case 'cleanup':
        this.logger.log('[Reports] Running cleanup');
        this.reportsService.cleanup();
        break;
      default:
        this.logger.warn(`Unknown job: ${job.name}`);
    }
  }
}
