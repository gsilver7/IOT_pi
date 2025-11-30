import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot(),

    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        transport: {
          host: configService.get<string>('SMTP_HOST') || 'smtp.gmail.com',
          port: configService.get<number>('SMTP_PORT') || 587, // 587로 변경
          secure: false, // 587 포트는 반드시 false
          auth: {
            user: configService.get<string>('EMAIL_USER'),
            pass: configService.get<string>('EMAIL_PASSWORD'),
          },
          tls: {
            rejectUnauthorized: false,
          },
        },
        defaults: {
          from: `"My Project" <${configService.get('EMAIL_USER')}>`,
        },
      }),
      inject: [ConfigService],
    }),
  ],
})
export class MailerAppModule {}
