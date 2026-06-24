import { Module } from '@nestjs/common';
import { SoarController } from './soar.controller';
import { SoarService } from './soar.service';

@Module({
  controllers: [SoarController],
  providers: [SoarService],
  exports: [SoarService],
})
export class SoarModule {}
