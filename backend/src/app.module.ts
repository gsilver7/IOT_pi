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
import { HttpModule } from '@nestjs/axios';
import { WeatherModule } from './weather/weather.module';
import { SerialModule } from './serial/serial.module';
import { EventEmitterModule } from '@nestjs/event-emitter';

@Module({
  imports: [ConfigModule.forRoot({
      isGlobal: true, // 전역으로 사용
      envFilePath: '.env', // .env 파일 경로
    }),
     HttpModule.register({
      timeout: 5000, // 요청 시간 초과 5초
    }),
    ScheduleModule.forRoot(),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGOURL'), // ConfigService를 사용해 환경변수 조회
      }),
      inject: [ConfigService], // ConfigService를 주입
    }),EventEmitterModule.forRoot({wildcard: true,
      delimiter: '.',}),
    PythonModule,EventsModule, UsbModule,StreamModule,WeatherModule, SerialModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

