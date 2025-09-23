import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({
  cors: {
    origin: 'http://localhost:3000',
  },
})
export class EventsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

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
  handleMessage(client: Socket, payload: string): void {
    console.log(`Received message from ${client.id}: ${payload}`);
    this.server.emit('message', payload); // 모든 클라이언트에게 메시지 브로드캐스트
  }
}