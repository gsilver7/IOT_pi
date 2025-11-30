import {
  UseGuards,
  Request,
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SendVerificationEmailDto } from './dto/send-email.dto';
import { RegisterDto } from './dto/register.dto';
import { AuthGuard } from '@nestjs/passport'; // 이거 import 필수

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
  @Post('refresh')
  async refresh(@Body() body: { userId: string; refreshToken: string }) {
    return this.authService.refresh(body.userId, body.refreshToken);
  }

  // 2. 로그아웃 API
  // (보통 로그아웃은 로그인된 상태에서 하므로 UseGuards(JwtAuthGuard)가 붙습니다)
  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  async logout(@Request() req) {
    // req.user는 JwtStrategy에서 파싱된 유저 정보 (payload)
    return this.authService.logout(req.user.sub);
  }
}
