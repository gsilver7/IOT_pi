import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { FaceController } from './face.controller';
import { FaceService } from './face.service';
import { User } from '../user/user.entity';
import { EventsGateway } from '../socket/socket.gateway';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [FaceController],
  providers: [FaceService,EventsGateway],
})
export class FaceModule {}