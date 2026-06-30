import { Module } from '@nestjs/common';
import { SoarController } from './soar.controller';
import { SoarService } from './soar.service';
import { PfSenseClientService } from './pfsense-client.service';

@Module({
  controllers: [SoarController],
  providers: [SoarService, PfSenseClientService],
  exports: [SoarService],
})
export class SoarModule {}
