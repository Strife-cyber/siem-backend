import { Module } from '@nestjs/common';
import { RulesController } from './rules.controller';

@Module({
  controllers: [RulesController]
})
export class RulesModule {}
