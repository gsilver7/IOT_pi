import { Module } from '@nestjs/common';
import { UsbService } from './usb.service';
import { UsbController } from './usb.controller';

@Module({
  imports: [],
  controllers: [UsbController], //프론트 요청
  providers: [UsbService],
  exports: [UsbService], // 👈 여기에서 UsbService를 export합니다.
})
export class UsbModule {}