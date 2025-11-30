import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger'; // Swagger 사용 시 추가

/**
 * 이메일 인증 코드 발송 요청 시 클라이언트에서 전달받는 데이터 구조 (DTO)
 */
export class SendVerificationEmailDto {
  // Swagger 문서화를 위한 데코레이터 (선택 사항)
  @ApiProperty({
    example: 'user@example.com',
    description: '인증 코드를 받을 사용자의 이메일 주소',
  })

  // 필수 값인지 검증합니다.
  @IsNotEmpty({ message: '이메일 주소는 필수입니다.' })

  // 문자열인지 검증합니다.
  @IsString({ message: '이메일은 문자열 형식이어야 합니다.' })

  // 실제 이메일 형식인지 검증합니다.
  @IsEmail({}, { message: '유효한 이메일 주소를 입력해야 합니다.' })
  email: string;
}
