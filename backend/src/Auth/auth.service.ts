import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VerificationCode } from 'src/entities/verification-code.entity';
import { User } from '../user/user.entity';
import { MailerService } from '@nestjs-modules/mailer';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';

export class RegisterDto {
  email: string;
  name: string;
  password: number;
  face: string;
  bluetooth: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(VerificationCode)
    private verificationCodeRepository: Repository<VerificationCode>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private userService: UserService,
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  /**
   * 6자리 랜덤 인증 코드를 생성합니다.
   */
  private generateVerificationCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  /**
   * 이메일 인증 코드를 생성하고 DB에 저장 후 발송합니다.
   */
  async sendVerificationEmail(email: string): Promise<void> {
    const code = this.generateVerificationCode();
    const expiryMinutes = 5;

    try {
      // 기존 인증 코드 삭제
      await this.verificationCodeRepository.delete({ email });

      // 새 인증 코드 저장
      await this.verificationCodeRepository.save({
        email,
        code,
        expiresAt: new Date(Date.now() + expiryMinutes * 60000),
      });

      console.log(`✅ DB 저장 성공: ${code} for ${email}`);

      // 이메일 발송
      await this.mailerService.sendMail({
        to: email,
        subject: '[MyProject] 회원가입 인증 코드입니다.',
        html: `
          <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
              <h1 style="color: white; margin: 0; text-align: center;">이메일 인증</h1>
            </div>
            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
              <p style="font-size: 16px; color: #333;">안녕하세요!</p>
              <p style="font-size: 16px; color: #333;">요청하신 인증 코드는 다음과 같습니다:</p>
              
              <div style="background: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">인증 코드</p>
                <p style="margin: 0; font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 8px;">${code}</p>
              </div>
              
              <p style="font-size: 14px; color: #666;">
                ⏰ 이 코드는 <strong>${expiryMinutes}분간</strong> 유효합니다.
              </p>
              <p style="font-size: 14px; color: #666;">
                ⚠️ 본인이 요청하지 않았다면 이 메일을 무시하세요.
              </p>
            </div>
            <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
              <p>본 메일은 자동 발송된 메일입니다.</p>
            </div>
          </div>
        `,
      });

      console.log(`✅ 이메일 발송 성공: ${email}`);
    } catch (error) {
      console.error('❌ 처리 실패:', error);
      throw new BadRequestException('이메일 발송에 실패했습니다.');
    }
  }

  /**
   * 인증 코드를 검증합니다.
   */
  async verifyCode(email: string, code: string): Promise<boolean> {
    try {
      const verificationCode = await this.verificationCodeRepository.findOne({
        where: { email, code, isUsed: false },
      });

      if (!verificationCode) {
        console.log(`❌ 인증 코드를 찾을 수 없음: ${email}`);
        return false;
      }

      // 만료 시간 확인
      if (new Date() > verificationCode.expiresAt) {
        console.log(`❌ 인증 코드 만료됨: ${email}`);
        return false;
      }

      // 사용 처리
      verificationCode.isUsed = true;
      await this.verificationCodeRepository.save(verificationCode);

      console.log(`✅ 인증 성공: ${email}`);
      return true;
    } catch (error) {
      console.error('❌ 인증 코드 검증 실패:', error);
      return false;
    }
  }

  /**
   * 회원가입을 처리합니다.
   */
  async register(
    registerDto: RegisterDto,
  ): Promise<{ message: string; user: any }> {
    const { email, name, password, face, bluetooth } = registerDto;

    try {
      // 1. 이메일 중복 체크
      const existingUser = await this.userRepository.findOne({
        where: { email },
      });

      if (existingUser) {
        throw new ConflictException('이미 가입된 이메일입니다.');
      }

      // 2. 사용자 생성
      const user = this.userRepository.create({
        email,
        name,
        password,
        face: face || '',
        bluetooth: bluetooth || '',
      });

      await this.userRepository.save(user);

      console.log(`✅ 회원가입 성공: ${email}`);

      // 3. 비밀번호 제외하고 반환
      const { password: _, ...userWithoutPassword } = user;

      return {
        message: '회원가입이 완료되었습니다.',
        user: userWithoutPassword,
      };
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      console.error('❌ 회원가입 실패:', error);
      throw new BadRequestException('회원가입에 실패했습니다.');
    }
  }
  async login(email: string, password: number) {
    console.log('로그인 시도:', email);

    // 1. DB에서 유저 찾기
    const user = await this.userService.findByEmail(email);
    console.log('유저 찾기 결과:', user ? '존재' : '없음');
    if (!user) {
      throw new UnauthorizedException('이메일 또는 비밀번호가 잘못되었습니다');
    }

    // 2. 비밀번호 검증
    const isPasswordValid = await this.userService.validatePassword(
      password.toString(),
      user.password.toString(),
    );
    console.log('비밀번호 검증:', isPasswordValid);

    if (!isPasswordValid) {
      throw new UnauthorizedException('이메일 또는 비밀번호가 잘못되었습니다');
    }

    // 3. JWT 토큰 발급
    const payload = { email: user.email, sub: user.id, name: user.name };
    return {
      access_token: this.jwtService.sign(payload),
      userId: user.id,
      email: user.email,
      name: user.name,
    };
  }
}
