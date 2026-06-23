import {
  IsString,
  IsOptional,
  MinLength,
  MaxLength,
  IsEnum,
} from 'class-validator';
import { UserRole } from '../../../generated/prisma/enums';

export class SignUpDto {
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  username!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(255)
  password!: string;

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}
