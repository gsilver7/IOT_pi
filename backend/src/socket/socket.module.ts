// events.module.ts
import { Module } from '@nestjs/common';
import { EventsGateway } from './socket.gateway';

@Module({
  providers: [EventsGateway], // 👈 여기에 등록해야 Gateway가 활성화됨
})
export class EventsModule {}
