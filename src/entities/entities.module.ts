import { Module } from '@nestjs/common';
import { EntityGraphService } from './entity-graph.service';
import { RiskScoringService } from './risk-scoring.service';

@Module({
  providers: [EntityGraphService, RiskScoringService],
  exports: [EntityGraphService, RiskScoringService],
})
export class EntitiesModule {}
