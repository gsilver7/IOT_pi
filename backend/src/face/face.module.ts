import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { FaceController } from './face.controller';
import { FaceService } from './face.service';
import { User } from '../user/user.entity';
import { StreamModule } from 'src/stream/stream.module';
import { PassportModule } from '@nestjs/passport'; // 👈 추가
import { AuthModule } from '../Auth/auth.module'; // 👈 import
import { UserModule } from 'src/user/user.module';

@Module({
  imports: [UserModule,PassportModule,TypeOrmModule.forFeature([User]),StreamModule,AuthModule],
  controllers: [FaceController],
  providers: [FaceService],
})
export class FaceModule {}