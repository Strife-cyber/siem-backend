import { Module } from '@nestjs/common';
import { SoarController } from './soar.controller';

@Module({
  controllers: [SoarController]
})
export class SoarModule {}
