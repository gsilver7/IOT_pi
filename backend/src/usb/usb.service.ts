// src/usb/usb.service.ts

import { Injectable, Logger } from '@nestjs/common';
import * as usb from 'usb';

@Injectable()
export class UsbService {
  private readonly logger = new Logger(UsbService.name);

  // 예시: 벤더 ID(VID)와 제품 ID(PID)로 장치 찾기
  // 이 값은 실제 USB 장치의 ID로 바꿔주세요.
  private readonly VENDOR_ID = 0x1234; // 예시 VID
  private readonly PRODUCT_ID = 0x5678; // 예시 PID

  constructor() {
    this.logger.log('USB Service 초기화');
  }

  findAllDevices(): usb.Device[] {
    return usb.getDeviceList();
  }

  findSpecificDevice(): usb.Device | null {
    const device = usb.findByIds(this.VENDOR_ID, this.PRODUCT_ID);
    if (!device) {
      this.logger.warn(`USB 장치를 찾을 수 없습니다: VID=${this.VENDOR_ID}, PID=${this.PRODUCT_ID}`);
      return null;
    }
    this.logger.log(`USB 장치를 찾았습니다: ${device.deviceDescriptor.iProduct}`);
    return device;
  }

  connectDevice(): void {
    const device = this.findSpecificDevice();
    if (device) {
      try {
        device.open();
        this.logger.log('USB 장치에 성공적으로 연결되었습니다.');
        // 추가적인 통신 로직을 여기에 구현할 수 있습니다.
        // 예: device.interfaces[0].claim();
        // device.interfaces[0].endpoints[0].transfer(data, callback);
        device.close(); // 예시이므로 바로 연결을 닫습니다.
      } catch (error) {
        this.logger.error('USB 장치 연결 실패:', error);
      }
    }
  }
}