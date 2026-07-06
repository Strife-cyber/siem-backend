import { IsString, IsOptional, IsIn } from 'class-validator';

const VALID_STATUSES = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'] as const;

export class UpdateFlagDto {
  @IsOptional()
  @IsString()
  reason?: string;

  @IsOptional()
  @IsIn(VALID_STATUSES)
  status?: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

  @IsOptional()
  @IsString()
  investigation_id?: string;
}
