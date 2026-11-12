import { Test, TestingModule } from '@nestjs/testing';
import { getQueueToken } from '@nestjs/bullmq';
import { LogsService } from './logs.service';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';

describe('LogsService', () => {
  let service: LogsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LogsService,
        { provide: getQueueToken('logs'), useValue: { add: jest.fn() } },
        { provide: ElasticsearchService, useValue: {} },
      ],
    }).compile();

    service = module.get<LogsService>(LogsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
