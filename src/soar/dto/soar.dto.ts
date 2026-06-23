import { IsString, IsUUID, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class PlaybookExecutionDto {
  @ApiProperty()
  @IsUUID()
  incident_id!: string;

  @ApiProperty({ enum: ['block_ip', 'disable_account', 'notify_teams'] })
  @IsString()
  playbook_name!: string;

  @ApiProperty({ enum: ['AUTO', 'CONFIRM'] })
  @IsEnum(['AUTO', 'CONFIRM'] as const)
  mode!: 'AUTO' | 'CONFIRM';
}

export class AbortPlaybookDto {
  @ApiProperty()
  @IsUUID()
  execution_id!: string;
}
