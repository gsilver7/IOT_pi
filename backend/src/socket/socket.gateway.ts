import { Logger } from '@nestjs/common';
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,  
  MessageBody,
  ConnectedSocket 
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import {Interval} from '@nestjs/schedule';
import { OnEvent } from '@nestjs/event-emitter';

@WebSocketGateway({
  cors: {namespace: 'chat',
    origin: 'http://localhost:3000/',
    methods: ['GET', 'POST'],
  },
})
export class EventsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(EventsGateway.name);

  // 클라이언트 연결 시 실행
  handleConnection(client: Socket) {
    console.log(`Client connected: ${client.id}`);
  }

  // 클라이언트 연결 해제 시 실행
  handleDisconnect(client: Socket) {
    console.log(`Client disconnected: ${client.id}`);
  }

  // 'message' 이벤트를 받으면 실행
  @SubscribeMessage('message')
    // @MessageBody()와 @ConnectedSocket() 데코레이터를 추가합니다.
    handleMessage(
      @MessageBody() payload: string,
      @ConnectedSocket() client: Socket,
    ): void {
    console.log(`Received message from ${client.id}: ${payload}`);

  }
  @OnEvent('tempdata')
  handleSerialData(payload: { type: string; value: string }) {
    console.log(`[SocketGateway] Broadcasting serial data: ${payload.value}`);
    
    this.server.emit('tempdata', payload);
  }

  @Interval(10000)
  handleInterval() {
    const message = {
      type: 'server-time',
      timestamp: new Date().toISOString(),};
    this.server.emit('server-time',message);
    this.logger.log('서버 시간 방송');
  }
}

