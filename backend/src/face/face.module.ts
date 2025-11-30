import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { FaceController } from './face.controller';
import { FaceService } from './face.service';
import { User } from '../user/user.entity';
import { StreamModule } from 'src/stream/stream.module';
import { PassportModule } from '@nestjs/passport'; // 👈 추가


@Module({
  imports: [PassportModule,TypeOrmModule.forFeature([User]),StreamModule],
  controllers: [FaceController],
  providers: [FaceService],
})
export class FaceModule {}