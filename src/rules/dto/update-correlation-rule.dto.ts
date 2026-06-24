import {
  IsString,
  IsOptional,
  IsBoolean,
  IsInt,
  Min,
  IsObject,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateCorrelationRuleDto {
  @ApiPropertyOptional({ example: 'SSH Brute Force' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsObject()
  definition?: Record<string, unknown>;

  @ApiPropertyOptional({ example: 'TA0001' })
  @IsOptional()
  @IsString()
  tactic?: string;

  @ApiPropertyOptional({ example: 'T1110' })
  @IsOptional()
  @IsString()
  technique?: string;

  @ApiPropertyOptional({ default: 1 })
  @IsOptional()
  @IsInt()
  @Min(0)
  confidence_weight?: number;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  is_active?: boolean;
}
