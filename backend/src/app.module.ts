import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { EventsModule } from './socket/socket.module';
import { UsbModule } from './usb/usb.module';
import { WebrtcModule } from './webrtc/webrtc.module';
import { MongooseModule } from '@nestjs/mongoose';



const mongourl = 'mongodb+srv://chatKMJ:rlaaudwns7@chatkmj.ezcjvwv.mongodb.net/?retryWrites=true&w=majority&appName=chatKMJ'

@Module({
  imports: [EventsModule, UsbModule,WebrtcModule,MongooseModule.forRoot(mongourl),],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
