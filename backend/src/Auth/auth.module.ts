import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { VerificationCode } from '../entities/verification-code.entity';
import { User } from 'src/user/user.entity';
import { UserModule } from 'src/user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

@Module({
  // ⚠️ TypeOrmModule을 통해 VerificationCode 엔티티를 사용하도록 설정
  imports: [
    TypeOrmModule.forFeature([VerificationCode, User]),
    UserModule,
    PassportModule,
    JwtModule.register({
      secret: 'your-secret-key',
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
  // AuthGuard 등 다른 모듈에서 AuthService를 사용하려면 exports에 추가해야 합니다.
  exports: [AuthService],
})
export class AuthModule {}
