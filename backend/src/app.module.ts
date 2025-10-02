import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { EventsModule } from './socket/socket.module';
import { UsbModule } from './usb/usb.module';
import { MongooseModule } from '@nestjs/mongoose';
import {StreamModule} from './stream/stream.module';
import {PythonModule} from './python/python.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import {ScheduleModule} from '@nestjs/schedule';



@Module({
  imports: [ConfigModule.forRoot({
      isGlobal: true, // 전역으로 사용
      envFilePath: '.env', // .env 파일 경로
    }),
    ScheduleModule.forRoot(),
    MongooseModule.forRootAsync({
      imports: [ConfigModule], // ConfigModule을 import
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGOURL'), // ConfigService를 사용해 환경변수 조회
      }),
      inject: [ConfigService], // ConfigService를 주입
    }),
    PythonModule,EventsModule, UsbModule,StreamModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

