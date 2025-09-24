// src/usb/usb.controller.ts

import { Controller, Get, Logger, InternalServerErrorException } from '@nestjs/common';
import { UsbService } from './usb.service';

@Controller('usb')
export class UsbController {
  private readonly logger = new Logger(UsbController.name);

  constructor(private readonly usbService: UsbService) {}

  @Get('list')
  listDevices(): any {
    this.logger.log('USB 장치 목록 요청 받음');
    const devices = this.usbService.findAllDevices();
    return devices.map(device => ({
      vendorId: device.deviceDescriptor.idVendor,
      productId: device.deviceDescriptor.idProduct,
      busNumber: device.busNumber,
      deviceAddress: device.deviceAddress,
    }));
  }

  @Get('connect')
  connectDevice(): string {
    this.logger.log('USB 장치 연결 요청 받음');
    try {
      this.usbService.connectDevice();
      return 'USB 장치 연결을 시도했습니다.';
    } catch (error) {
      throw new InternalServerErrorException('USB 장치 연결에 실패했습니다.');
    }
  }
}