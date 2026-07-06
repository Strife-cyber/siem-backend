import { IsString, IsOptional, IsObject } from 'class-validator';

export class FlagEventDto {
  @IsString()
  ingestion_hash!: string;

  @IsOptional()
  @IsString()
  reason?: string;

  @IsOptional()
  @IsObject()
  event_snapshot?: Record<string, unknown>;
}
