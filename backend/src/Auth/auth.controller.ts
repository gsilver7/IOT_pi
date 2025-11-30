// Auth.controller.ts → auth.controller.ts (소문자로)
import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SendVerificationEmailDto } from './dto/send-email.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('send-verification-email')
  async sendVerificationEmail(@Body() sendEmailDto: SendEmailDto) {
    // DTO 전체를 전달하거나, email만 전달
    return this.authService.sendVerificationEmail(sendEmailDto.email);
  }
  @HttpCode(HttpStatus.OK)
  async sendVerificationEmail(@Body() sendEmailDto: SendVerificationEmailDto) {

    await this.authService.sendVerificationEmail(sendEmailDto.email);

    return {
      message: '인증 코드가 이메일로 성공적으로 발송되었습니다.',
      email: sendEmailDto.email,
    };
  }

  // 인증 코드 검증 엔드포인트 추가
  @Post('verify-code')
  @HttpCode(HttpStatus.OK)
  async verifyCode(@Body() body: { email: string; code: string }) {
    const isValid = await this.authService.verifyCode(body.email, body.code);

    if (!isValid) {
      return {
        success: false,
        message: '인증 코드가 유효하지 않거나 만료되었습니다.',
      };
    }

    return {
      success: true,
      message: '인증이 완료되었습니다.',
    };
  }
}