import {
  IsString,
  IsEnum,
  IsArray,
  IsOptional,
  IsDateString,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ReportGenerationDto {
  @ApiProperty()
  @IsDateString()
  start_date!: string;

  @ApiProperty()
  @IsDateString()
  end_date!: string;

  @ApiProperty({ enum: ['pdf', 'excel'] })
  @IsEnum(['pdf', 'excel'] as const)
  format!: 'pdf' | 'excel';

  @ApiPropertyOptional()
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  incident_ids?: string[];
}
