import { Module } from '@nestjs/common';
import { UebaController } from './ueba.controller';
import { UebaService } from './ueba.service';

@Module({
  controllers: [UebaController],
  providers: [UebaService],
})
export class UebaModule {}
