import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { EventsModule } from './socket/socket.module';
import { UsbModule } from './usb/usb.module';
import { StreamModule } from './stream/stream.module';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { HttpModule } from '@nestjs/axios';
import { WeatherModule } from './weather/weather.module';
import { SerialModule } from './serial/serial.module';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './user/user.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // 전역으로 사용
      envFilePath: '.env', // .env 파일 경로
    }),
    HttpModule.register({
      timeout: 5000, // 요청 시간 초과 5초
    }),
    ScheduleModule.forRoot(),
    // TypeOrmModule.forRoot({
    //   type: 'mysql', // 또는 'postgres'
    //   host: process.env.DB_HOST,
    //   port: parseInt(process.env.DB_PORT),
    //   username: process.env.DB_USERNAME,
    //   password: process.env.DB_PASSWORD,
    //   database: process.env.DB_DATABASE,
    //   entities: [__dirname + '/**/*.entity{.ts,.js}'],
    //   synchronize: false, // 프로덕션에서는 false
    // }),
    EventEmitterModule.forRoot({ wildcard: true, delimiter: '.' }),
    // PythonModule,
    EventsModule,
    UsbModule,
    StreamModule,
    // UserModule,
    WeatherModule,
    SerialModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
