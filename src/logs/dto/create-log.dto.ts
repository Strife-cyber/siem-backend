import {
  IsString,
  IsOptional,
  IsInt,
  Min,
  Max,
  IsDateString,
  IsIP,
  IsArray,
} from 'class-validator';

export class CreateLogDto {
  @IsDateString()
  collected_at!: string;

  @IsString()
  source_type!: string;

  @IsString()
  hostname!: string;

  @IsIP()
  source_ip!: string;

  @IsOptional()
  @IsIP()
  destination_ip?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(65535)
  source_port?: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(65535)
  destination_port?: number;

  @IsOptional()
  @IsString()
  user_principal?: string;

  @IsOptional()
  @IsString()
  user_security_id?: string;

  @IsString()
  event_taxonomy!: string;

  @IsString()
  action!: string;

  @IsOptional()
  @IsString()
  outcome?: string;

  @IsInt()
  @Min(0)
  @Max(7)
  severity!: number;

  @IsString()
  raw_message!: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];
}
