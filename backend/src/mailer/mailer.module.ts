import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    // ConfigModule을 가져와 환경 변수를 사용할 수 있도록 설정
    ConfigModule.forRoot(),

    // MailerModule을 동적으로 설정 (ConfigService를 주입하기 위해 useFactory 사용)
    MailerModule.forRootAsync({
      // ConfigService를 MailerModule에 주입할 수 있도록 설정
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        // ⚠️ host, port, auth 정보를 환경 변수에서 가져와 설정합니다.
        transport: {
          host: configService.get<string>('SMTP_HOST') || 'smtp.gmail.com', // .env 파일에 SMTP_HOST 설정
          port: configService.get<number>('SMTP_PORT') || 587,
          secure: configService.get<boolean>('SMTP_SECURE') || false, // 587 포트일 경우 false
          auth: {
            user: configService.get<string>('EMAIL_USER'), // 발신자 이메일 주소
            pass: configService.get<string>('EMAIL_PASSWORD'), // 앱 비밀번호
          },
        },
        defaults: {
          // 모든 메일에 기본적으로 적용될 발신자 정보
          from: `"My Project" <${configService.get('EMAIL_USER')}>`,
        },
        // 템플릿 엔진 설정 (선택 사항: handlebars, pug 등을 사용할 때)
        // template: {
        //   dir: __dirname + '/templates', // 템플릿 파일 경로
        //   adapter: new HandlebarsAdapter(),
        //   options: {
        //     strict: true,
        //   },
        // },
      }),
      inject: [ConfigService], // useFactory에 ConfigService 주입
    }),
  ],
})
export class MailerAppModule {}
