import { IsString, MinLength, MaxLength } from 'class-validator';

export class SignInDto {
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  username!: string;

  @IsString()
  @MinLength(6)
  @MaxLength(255)
  password!: string;
}
