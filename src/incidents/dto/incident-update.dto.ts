import { IsOptional, IsString, IsUUID } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class IncidentStatusEnum {
  static IN_PROGRESS = 'IN_PROGRESS';
  static RESOLVED = 'RESOLVED';
  static FALSE_POSITIVE = 'FALSE_POSITIVE';
}

export class IncidentUpdateDto {
  @ApiPropertyOptional({ enum: ['IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'] })
  @IsOptional()
  @IsString()
  status?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  summary?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  assigned_to?: string;
}
