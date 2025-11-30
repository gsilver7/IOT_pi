import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { IoAdapter } from '@nestjs/platform-socket.io'; // IoAdapter 임포트
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // IoAdapter를 소켓 어댑터로 등록
  app.useWebSocketAdapter(new IoAdapter(app));
  app.setGlobalPrefix('api');

  // CORS 설정 (프론트엔드와 통신하기 위해 필요)
  app.enableCors({
    origin: '*', // 프론트엔드 URL
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // DTO에 정의되지 않은 값은 거름 (보안)
      forbidNonWhitelisted: true, // 이상한 값 들어오면 에러 냄
      transform: true, // url 파라미터를 숫자로 자동 변환 등
    }),
  );

  await app.listen(4000, '0.0.0.0');
  console.log('서버가 4000번 포트에서 실행 중입니다.');
}
bootstrap();
