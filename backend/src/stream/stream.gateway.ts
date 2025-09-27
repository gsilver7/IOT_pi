// stream.gateway.ts
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Logger } from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { StreamService } from './stream.service';

@WebSocketGateway({
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
})
export class StreamGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(StreamGateway.name);

  constructor(private readonly streamService: StreamService) {}

  handleConnection(client: Socket): void {
    this.logger.log(`WebSocket client connected: ${client.id}`);
    
    // 클라이언트에게 서버 상태 전송
    client.emit('server_status', {
      status: 'ready',
      streamUrl: '/stream',
      timestamp: Date.now(),
    });
  }

  handleDisconnect(client: Socket): void {
    this.logger.log(`WebSocket client disconnected: ${client.id}`);
  }

  @SubscribeMessage('request_stream_info')
  handleStreamInfo(@ConnectedSocket() client: Socket): void {
    const stats = this.streamService.getStreamStats();
    client.emit('stream_info', {
      ...stats,
      timestamp: Date.now(),
    });
  }

  @SubscribeMessage('ping')
  handlePing(
    @MessageBody() data: any,
    @ConnectedSocket() client: Socket,
  ): void {
    client.emit('pong', {
      message: 'NestJS Stream Server',
      timestamp: Date.now(),
      clientId: client.id,
    });
  }

  // 모든 클라이언트에게 스트림 상태 브로드캐스트
  broadcastStreamStatus(): void {
    const stats = this.streamService.getStreamStats();
    this.server.emit('stream_status_update', {
      ...stats,
      timestamp: Date.now(),
    });
  }
}