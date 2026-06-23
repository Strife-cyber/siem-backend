import { Queue } from 'bullmq';
import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';

@Injectable()
export class LogsService {
  constructor(
    @InjectQueue('logs')
    private readonly logsQueue: Queue,
  ) {}

  async ingest(logs: any[]) {
    await this.logsQueue.add('normalize', { logs });

    return {
      accepted: logs.length,
    };
  }
}
