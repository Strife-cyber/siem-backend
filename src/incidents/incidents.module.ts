import { Module } from '@nestjs/common';
import { IncidentsController } from './incidents.controller';

@Module({
  controllers: [IncidentsController]
})
export class IncidentsModule {}
