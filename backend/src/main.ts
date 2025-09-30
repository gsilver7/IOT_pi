import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { IoAdapter } from '@nestjs/platform-socket.io'; // IoAdapter 임포트

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // IoAdapter를 소켓 어댑터로 등록
  app.useWebSocketAdapter(new IoAdapter(app));
  
  // CORS 설정 (프론트엔드와 통신하기 위해 필요)
  app.enableCors({
    origin: 'http://192.168.137.154:3000/', // 프론트엔드 URL
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });

    await app.listen(4000, '0.0.0.0');
    console.log('서버가 4000번 포트에서 실행 중입니다.');
}
bootstrap();