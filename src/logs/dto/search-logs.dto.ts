import {
  IsString,
  IsOptional,
  IsInt,
  Min,
  Max,
  IsArray,
} from 'class-validator';
import { Type } from 'class-transformer';

export class SearchLogsDto {
  @IsOptional()
  @IsString()
  source_ip?: string;

  @IsOptional()
  @IsString()
  destination_ip?: string;

  @IsOptional()
  @IsString()
  user_principal?: string;

  @IsOptional()
  @IsString()
  hostname?: string;

  @IsOptional()
  @IsString()
  source_type?: string;

  @IsOptional()
  @IsString()
  event_taxonomy?: string;

  @IsOptional()
  @IsString()
  action?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(7)
  severity_min?: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(7)
  severity_max?: number;

  @IsOptional()
  @IsString()
  raw_message?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @IsOptional()
  @IsString()
  date_from?: string;

  @IsOptional()
  @IsString()
  date_to?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  from?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(10000)
  size?: number;

  @IsOptional()
  @IsString()
  sort_field?: string;

  @IsOptional()
  @IsString()
  sort_order?: 'asc' | 'desc';
}
