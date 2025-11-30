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
import { MailerAppModule } from './mailer/mailer.module';
import { AuthModule } from './Auth/auth.module';
import { RedisModule } from '@nestjs-modules/ioredis';

@Module({
  imports: [
    RedisModule.forRoot({
      type: 'single',
      url: 'redis://redis:6379', // 컨테이너명 사용
      // 또는
      options: {
        host: process.env.REDIS_HOST || 'redis',
        port: parseInt(process.env.REDIS_PORT) || 6379,
      },
    }),
    ConfigModule.forRoot({
      isGlobal: true, // 전역으로 사용
      envFilePath: '.env', // .env 파일 경로
    }),
    HttpModule.register({
      timeout: 5000, // 요청 시간 초과 5초
    }),
    ScheduleModule.forRoot(),
    TypeOrmModule.forRoot({
      type: 'mysql', // 또는 'postgres'
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT),
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true, // 이거 true로!
      logging: true, // 로그도 켜서 확인
    }),
    EventEmitterModule.forRoot({ wildcard: true, delimiter: '.' }),
    // PythonModule,
    EventsModule,
    UsbModule,
    StreamModule,
    UserModule,
    WeatherModule,
    MailerAppModule,
    SerialModule,
    MailerAppModule, // 추가
    AuthModule, // 추가
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
