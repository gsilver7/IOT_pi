import { Module } from '@nestjs/common';
import { SerialService } from './serial.service';
import { SerialController } from './serial.controller';

@Module({
  providers: [SerialService],
  exports: [SerialService],
  controllers: [SerialController], // 다른 모듈에서 사용 가능하도록 export
})
export class SerialModule {}