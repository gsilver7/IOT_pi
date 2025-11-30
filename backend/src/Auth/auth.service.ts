import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { SendVerificationEmailDto } from './dto/send-email.dto';
// ⚠️ TypeORM 사용 시 아래 주석 해제 후 Entity 정의 필요
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VerificationCode } from '../entities/verification-code.entity';

@Injectable()
export class AuthService {
  // MailerService를 주입합니다.
  constructor(
    private readonly mailerService: MailerService,
    // ⚠️ TypeORM Repository 주입 (실제 사용 시 주석 해제)
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
   * @param sendEmailDto - 인증을 요청한 이메일 주소
   */
  async sendVerificationEmail(
    sendEmailDto: SendVerificationEmailDto,
  ): Promise<void> {
    const { email } = sendEmailDto;
    const code = this.generateVerificationCode();
    const expiryMinutes = 5; // 코드 유효 시간: 5분

    // 1. DB에 인증 코드 저장 (토이 프로젝트 간소화)
    try {
      // ⚠️ 실제 TypeORM 사용 시:
      await this.verificationCodeRepository.save({
        email,
        code,
        expiresAt: new Date(Date.now() + expiryMinutes * 60000),
      });

      console.log(
        `[DB Placeholder] Saving verification code ${code} for ${email}`,
      );
    } catch (dbError) {
      console.error('DB 저장 중 오류 발생:', dbError);
      throw new InternalServerErrorException('인증 코드 저장에 실패했습니다.');
    }

    // 2. 이메일 발송
    try {
      await this.mailerService.sendMail({
        to: email, // 수신자 이메일
        subject: '[MyProject] 회원가입 인증 코드입니다.', // 제목
        html: `
          <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ccc; border-radius: 8px;">
            <h2>회원가입 인증</h2>
            <p>요청하신 인증 코드입니다. 아래 코드를 <b>${expiryMinutes}분 이내</b>에 입력해 주세요.</p>
            <div style="font-size: 24px; font-weight: bold; background-color: #f0f0f0; padding: 10px; border-radius: 4px; text-align: center;">
              ${code}
            </div>
            <p style="color: #888; margin-top: 20px;">본 메일은 자동 발송된 메일입니다.</p>
          </div>
        `, // HTML 본문
      });
      console.log(`Verification email sent successfully to ${email}`);
    } catch (mailError) {
      console.error('이메일 발송 중 오류 발생:', mailError);
      throw new InternalServerErrorException(
        '이메일 발송에 실패했습니다. (SMTP 설정 확인 필요)',
      );
    }
  }
  async verifyCode(email: string, code: string): Promise<boolean> {
    const verificationCode = await this.verificationCodeRepository.findOne({
      where: { email, code, isUsed: false },
    });

    if (!verificationCode) {
      return false;
    }

    // 만료 시간 확인
    if (new Date() > verificationCode.expiresAt) {
      return false;
    }

    // 사용 처리
    verificationCode.isUsed = true;
    await this.verificationCodeRepository.save(verificationCode);

    return true;
  }
}
