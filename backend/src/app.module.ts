import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { EventsModule } from './socket/socket.module';
import { UsbModule } from './usb/usb.module';
import { MongooseModule } from '@nestjs/mongoose';
import {StreamModule} from './stream/stream.module';
import {PythonModule} from './python/python.module';
import { ConfigModule } from '@nestjs/config';

const mongourl = process.env.MONGOURL



@Module({
  imports: [PythonModule,EventsModule, UsbModule,StreamModule,
     ConfigModule.forRoot({
      isGlobal: true, // 전역으로 사용
      envFilePath: '.env', // .env 파일 경로
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

// MongooseModule.forRoot(mongourl),