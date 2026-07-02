import { IsOptional, IsInt, Min, IsString } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class DashboardOverviewQuery {
  @ApiPropertyOptional({ enum: ['16h', '24h', '7d', '30d'], default: '24h' })
  @IsOptional()
  @IsString()
  interval?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  source_type?: string;
}

export class DashboardTimelineQuery {
  @ApiPropertyOptional({ default: 24 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  hours?: number;
}
