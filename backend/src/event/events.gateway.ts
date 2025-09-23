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

@WebSocketGateway({
  cors: {
    origin: 'http://192.168.137.154:3000/',
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
    // @MessageBody()와 @ConnectedSocket() 데코레이터를 추가합니다.
    handleMessage(
      @MessageBody() payload: string,
      @ConnectedSocket() client: Socket,
    ): void {
    console.log(`Received message from ${client.id}: ${payload}`);

  }
}

