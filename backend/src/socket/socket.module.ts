// events.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EventsGateway } from './socket.gateway';
import { User } from '../user/user.entity'; // 경로는 프로젝트 구조에 맞게 수정


@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [EventsGateway], // 👈 여기에 등록해야 Gateway가 활성화됨
})
export class EventsModule {}
