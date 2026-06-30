import {
  IsString,
  IsUUID,
  IsEnum,
  IsOptional,
  IsInt,
  Min,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PlaybookExecutionDto {
  @ApiProperty()
  @IsUUID()
  incident_id!: string;

  @ApiProperty({
    enum: [
      'block_ip',
      'isolate_endpoint',
      'disable_account',
      'block_port',
      'temporary_block',
      'remove_rule',
      'create_alias',
      'delete_alias',
      'check_ip',
      'notify_teams',
    ],
  })
  @IsString()
  playbook_name!: string;

  @ApiProperty({ enum: ['AUTO', 'CONFIRM'] })
  @IsEnum(['AUTO', 'CONFIRM'] as const)
  mode!: 'AUTO' | 'CONFIRM';
}

export class DirectBlockIpDto {
  @ApiProperty({ description: 'IP address to block' })
  @IsString()
  ip!: string;

  @ApiPropertyOptional({ description: 'Reason for blocking' })
  @IsOptional()
  @IsString()
  reason?: string;
}

export class DirectBlockPortDto {
  @ApiProperty({ description: 'IP address to block' })
  @IsString()
  ip!: string;

  @ApiProperty({ default: 3389 })
  @IsInt()
  @Min(1)
  port!: number;

  @ApiProperty({ enum: ['tcp', 'udp'] })
  @IsEnum(['tcp', 'udp'] as const)
  protocol!: 'tcp' | 'udp';

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reason?: string;
}

export class DirectTempBlockDto {
  @ApiProperty({ description: 'IP address to block' })
  @IsString()
  ip!: string;

  @ApiProperty({ default: 1800, description: 'TTL in seconds' })
  @IsInt()
  @Min(60)
  ttl_seconds!: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  reason?: string;
}

export class DirectCheckIpDto {
  @ApiProperty()
  @IsString()
  ip!: string;
}

export class DirectAliasDto {
  @ApiProperty()
  @IsString()
  name!: string;

  @ApiProperty({ type: [String] })
  @IsString({ each: true })
  addresses!: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;
}

export class AbortPlaybookDto {
  @ApiProperty()
  @IsUUID()
  execution_id!: string;
}
