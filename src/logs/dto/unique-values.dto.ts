import { IsString, IsOptional, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class UniqueValuesDto {
  @ApiProperty({
    description:
      'Field to get unique values for (e.g. hostname, source_type, source_ip, action)',
    example: 'hostname',
  })
  @IsString()
  field!: string;

  @ApiProperty({
    required: false,
    description: 'Optional query to filter before aggregating',
  })
  @IsOptional()
  @IsString()
  q?: string;

  @ApiProperty({
    required: false,
    description: 'Maximum number of unique values to return',
    default: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(10000)
  size?: number;
}
