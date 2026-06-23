import { IsString, IsOptional, IsBoolean, IsEnum, MinLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty()
  @IsString()
  @MinLength(3)
  username!: string;

  @ApiProperty()
  @IsString()
  @MinLength(8)
  password!: string;

  @ApiProperty({ enum: ['READER', 'ANALYST', 'ADMIN'] })
  @IsEnum(['READER', 'ANALYST', 'ADMIN'] as const)
  role!: string;
}

export class UpdateUserDto {
  @ApiPropertyOptional({ enum: ['READER', 'ANALYST', 'ADMIN'] })
  @IsOptional()
  @IsEnum(['READER', 'ANALYST', 'ADMIN'] as const)
  role?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  is_active?: boolean;
}

export class UpdateRetentionDto {
  @ApiProperty()
  policy_id!: number;

  @ApiProperty()
  duration_days!: number;
}
