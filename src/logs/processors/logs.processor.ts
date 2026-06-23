import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';

@Processor('logs')
export class LogsProcessor extends WorkerHost {
  async process(job: Job<any>) {
    switch (job.name) {
      case 'normalize':
        await this.normalizeLogs(job.data.logs as any[]);
        break;
    }
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  private async normalizeLogs(logs: any[]) {
    // TODO: Implement log normalization logic
    console.log(`Processing ${logs.length} logs for normalization...`);
  }
}
