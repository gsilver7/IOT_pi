import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { EventsModule } from './socket/socket.module';
import { UsbModule } from './usb/usb.module';
import { MongooseModule } from '@nestjs/mongoose';
import {StreamModule} from './stream/stream.module';


const mongourl = 'mongodb+srv://chatKMJ:rlaaudwns7@chatkmj.ezcjvwv.mongodb.net/?retryWrites=true&w=majority&appName=chatKMJ'

@Module({
  imports: [EventsModule, UsbModule,StreamModule,MongooseModule.forRoot(mongourl),],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
