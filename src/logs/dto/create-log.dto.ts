import { IsString, IsDateString } from 'class-validator';

export class CreateLogDto {
  @IsDateString()
  timestamp!: string;

  @IsString()
  hostname!: string;

  @IsString()
  source!: string;

  @IsString()
  eventId!: number;

  @IsString()
  message!: string;
}
