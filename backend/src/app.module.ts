import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { EventsModule } from './socket/socket.module';
import { UsbModule } from './usb/usb.module';

@Module({
  imports: [EventsModule, UsbModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
