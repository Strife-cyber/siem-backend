import { IsString, IsUUID, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyMfaDto {
  @ApiProperty()
  @IsUUID()
  session_id!: string;

  @ApiProperty({ description: '6-digit code sent via email' })
  @IsString()
  @Length(6, 6)
  code!: string;
}

export class EnableMfaDto {
  @ApiProperty({ description: 'Email address for receiving OTP codes' })
  @IsString()
  email!: string;
}
