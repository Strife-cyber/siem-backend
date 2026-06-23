import { IsString, IsOptional, IsBoolean, IsInt, Min } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateCorrelationRuleDto {
  @ApiProperty({ example: 'R001' })
  @IsString()
  id!: string;

  @ApiProperty({ example: 'SSH Brute Force' })
  @IsString()
  name!: string;

  @ApiPropertyOptional({ example: 'TA0001' })
  @IsOptional()
  @IsString()
  tactic?: string;

  @ApiPropertyOptional({ example: 'T1110' })
  @IsOptional()
  @IsString()
  technique?: string;

  @ApiProperty({
    description: 'JSON rule definition (threshold, window, filters)',
  })
  definition!: Record<string, unknown>;

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
