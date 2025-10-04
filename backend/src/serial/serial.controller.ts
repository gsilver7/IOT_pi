import { Controller, Get, Param, HttpException, HttpStatus } from '@nestjs/common';
import { SerialService } from './serial.service';

@Controller('serial')
export class SerialController {
  constructor(private readonly serialService: SerialService) {}

  @Get('status')
  getSerialStatus(): { status: string; message: string } {
    const status = this.serialService.isPortOpen() ? 'open' : 'closed';
    const message = this.serialService.isPortOpen() 
        ? 'Serial port is currently open and ready.' 
        : 'Serial port is not open. Check the connection.';
    return { status, message };
  }

  @Get('write/:data')
  async writeData(@Param('data') data: string): Promise<{ status: string; message: string }> {
    if (!data) {
      throw new HttpException('Data parameter is required.', HttpStatus.BAD_REQUEST);
    }
    
    try {
      await this.serialService.writeData(data);
      return { status: 'success', message: `Data '${data}' sent to Arduino.` };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}