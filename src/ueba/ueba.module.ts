import { Module } from '@nestjs/common';
import { UebaController } from './ueba.controller';

@Module({
  controllers: [UebaController]
})
export class UebaModule {}
