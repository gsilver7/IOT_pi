import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VerificationCode } from './entities/verification-code.entity';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(VerificationCode)
    private verificationCodeRepository: Repository<VerificationCode>,
    private readonly mailerService: MailerService,
  ) {}

  async sendVerificationEmail(email: string) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    try {
      // 기존 인증 코드 삭제
      await this.verificationCodeRepository.delete({ email });

      // 새 인증 코드 저장
      const verificationCode = this.verificationCodeRepository.create({
        email,
        code,
        expiresAt,
      });
      await this.verificationCodeRepository.save(verificationCode);

      console.log(`✅ DB 저장 성공: ${code} for ${email}`);

      // 이메일 발송
      await this.mailerService.sendMail({
        to: email,
        subject: '이메일 인증 코드',
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
                ⏰ 이 코드는 <strong>5분간</strong> 유효합니다.
              </p>
              <p style="font-size: 14px; color: #666;">
                ⚠️ 본인이 요청하지 않았다면 이 메일을 무시하세요.
              </p>
            </div>
          </div>
        `,
      });

      console.log(`✅ 이메일 발송 성공: ${email}`);

      return { message: '인증 코드가 발송되었습니다.' };
    } catch (error) {
      console.error('❌ 처리 실패:', error);
      throw new Error('인증 코드 발송에 실패했습니다.');
    }
  }

  async verifyCode(email: string, code: string): Promise<boolean> {
    const record = await this.verificationCodeRepository.findOne({
      where: { email, code, isUsed: false },
    });

    if (!record) {
      return false;
    }

    // 만료 시간 확인
    if (new Date() > record.expiresAt) {
      return false;
    }

    // 사용 처리
    record.isUsed = true;
    await this.verificationCodeRepository.save(record);

    return true;
  }
}
