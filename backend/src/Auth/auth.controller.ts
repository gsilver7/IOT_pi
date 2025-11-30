import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SendVerificationEmailDto } from './dto/send-email.dto';
import { RegisterDto } from './dto/register.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('send-verification-email')
  @HttpCode(HttpStatus.OK)
  async sendVerificationEmail(@Body() sendEmailDto: SendVerificationEmailDto) {
    await this.authService.sendVerificationEmail(sendEmailDto.email);
    return {
      message: '인증 코드가 이메일로 성공적으로 발송되었습니다.',
      email: sendEmailDto.email,
    };
  }

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
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }
  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }
}
