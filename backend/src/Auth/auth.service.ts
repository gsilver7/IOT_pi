import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VerificationCode } from '../entities/verification-code.entity';

@Injectable()
export class AuthService {
  constructor(
    private readonly mailerService: MailerService,
    @InjectRepository(VerificationCode)
    private verificationCodeRepository: Repository<VerificationCode>,
  ) {}

  /**
   * 6자리 랜덤 인증 코드를 생성합니다.
   * @returns {string} 6자리 숫자 문자열
   */
  private generateVerificationCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  /**
   * 이메일 인증 코드를 생성하고 DB에 저장 후 발송합니다.
   * @param email - 인증을 요청한 이메일 주소
   */
  async sendVerificationEmail(email: string): Promise<void> {
    const code = this.generateVerificationCode();
    const expiryMinutes = 5; // 코드 유효 시간: 5분

    try {
      // 1. 기존 인증 코드 삭제 (중복 방지)
      await this.verificationCodeRepository.delete({ email });

      // 2. 새 인증 코드 저장
      await this.verificationCodeRepository.save({
        email,
        code,
        expiresAt: new Date(Date.now() + expiryMinutes * 60000),
      });

      console.log(`✅ DB 저장 성공: ${code} for ${email}`);

      // 3. 이메일 발송
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

      if (
        error.message?.includes('SMTP') ||
        error.message?.includes('ECONNREFUSED')
      ) {
        throw new InternalServerErrorException(
          '이메일 발송에 실패했습니다. SMTP 설정을 확인해주세요.',
        );
      }

      throw new InternalServerErrorException('인증 코드 처리에 실패했습니다.');
    }
  }

  /**
   * 인증 코드를 검증합니다.
   * @param email - 사용자 이메일
   * @param code - 입력한 인증 코드
   * @returns 유효 여부
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
}
