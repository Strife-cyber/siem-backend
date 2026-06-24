import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { CorrelationService } from './correlation.service';

@Processor('correlation', { concurrency: 2 })
export class CorrelationScheduler extends WorkerHost {
  private readonly logger = new Logger(CorrelationScheduler.name);

  constructor(private readonly correlationService: CorrelationService) {
    super();
  }

  async process(_job: Job<void>): Promise<void> {
    const cycleStart = Date.now();
    this.logger.log('[CYCLE] Correlation cycle started');

    try {
      const report = await this.correlationService.runCycle();

      const totalTime = Date.now() - cycleStart;
      this.logger.log(
        `[DONE] Cycle complete: ${totalTime}ms | ` +
          `${report.activeRuleCount} active rules | ` +
          `${report.totalIncidentsCreated} incident(s) created`,
      );
    } catch (error: any) {
      this.logger.error(
        `[FAIL] Correlation cycle crashed: ${error.message ?? error}`,
      );
    }
  }
}
