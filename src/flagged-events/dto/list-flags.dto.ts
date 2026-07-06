import { IsString, IsOptional, IsIn, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

const VALID_STATUSES = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'] as const;

export class ListFlagsDto {
  @IsOptional()
  @IsIn(VALID_STATUSES)
  status?: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

  @IsOptional()
  @IsString()
  investigation_id?: string;

  @IsOptional()
  @IsString()
  q?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  from?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  size?: number;
}
