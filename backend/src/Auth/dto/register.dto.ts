import { IsEmail, IsNotEmpty, IsString, IsNumber, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class RegisterDto {
  @IsEmail({}, { message: '유효한 이메일 주소를 입력해주세요.' })
  @IsNotEmpty({ message: '이메일은 필수입니다.' })
  email: string;

  @IsString({ message: '이름은 문자열이어야 합니다.' })
  @IsNotEmpty({ message: '이름은 필수입니다.' })
  name: string;

  @Type(() => Number)
  @IsNumber({}, { message: '비밀번호는 숫자여야 합니다.' })
  @Min(1000, { message: '비밀번호는 최소 4자리 이상이어야 합니다.' })
  password: number;

  @IsString()
  face: string;

  @IsString()
  bluetooth: string;
}
