import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { UebaScorerService } from './ueba-scorer.service';
import { UebaBaselineService } from './ueba-baseline.service';
import type { NormalizedLog } from '../logs/interfaces/normalized-log.interface';

interface UebaScoringJob {
  log: NormalizedLog;
}

interface UebaBaselineJob {
  // empty — triggers a full rebuild
}

@Processor('ueba', { concurrency: 5 })
export class UebaProcessor extends WorkerHost {
  private readonly logger = new Logger(UebaProcessor.name);

  constructor(
    private readonly uebaScorer: UebaScorerService,
    private readonly baselineService: UebaBaselineService,
  ) {
    super();
  }

  async process(job: Job<UebaScoringJob | UebaBaselineJob>): Promise<void> {
    switch (job.name) {
      case 'score': {
        const { log } = job.data as UebaScoringJob;
        return this.handleScoring(log);
      }
      case 'rebuild-baselines': {
        return this.handleRebuildBaselines();
      }
      default:
        this.logger.warn(`Unknown job type: ${job.name}`);
    }
  }

  private async handleScoring(log: NormalizedLog): Promise<void> {
    try {
      const result = await this.uebaScorer.scoreLog(log);

      if (result.triggered_soar) {
        this.logger.warn(
          `[UEBA] ${result.user_principal}: score ${result.risk_score_before} -> ${result.risk_score_after} [SOAR]`,
        );
      } else if (result.event_score > 40) {
        this.logger.log(
          `[UEBA] ${result.user_principal}: score ${result.risk_score_before} → ${result.risk_score_after} (event=${result.event_score})`,
        );
      }
    } catch (error: any) {
      this.logger.error(`[UEBA] Scoring failed: ${error.message}`);
    }
  }

  private async handleRebuildBaselines(): Promise<void> {
    this.logger.log('[UEBA] Nightly baseline rebuild started');
    try {
      const result = await this.baselineService.buildAllBaselines();
      this.logger.log(
        `[UEBA] Nightly baseline rebuild complete: ${result.usersProcessed} users`,
      );
    } catch (error: any) {
      this.logger.error(
        `[UEBA] Nightly baseline rebuild failed: ${error.message}`,
      );
    }
  }
}
