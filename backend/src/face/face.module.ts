import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { FaceController } from './face.controller';
import { FaceService } from './face.service';
import { User } from '../user/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [FaceController],
  providers: [FaceService],
})
export class FaceModule {}