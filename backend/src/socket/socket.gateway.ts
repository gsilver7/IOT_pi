import { Logger } from '@nestjs/common';
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Interval } from '@nestjs/schedule';
import { OnEvent } from '@nestjs/event-emitter';

interface AduDataDto {
  temp: string;
  humi: string;
  co2: string;
  light: string;
  timestamp: string;
  deviceId: string;
}

interface ControlMessage {
  light: boolean;
  w: boolean;
  fan: boolean;
  mode: string;
}

@WebSocketGateway({
  cors: {
    origin: 'https://kmj.shscript.com',
    credentials: true,
    methods: ['GET', 'POST'],
  },
  transports: ['websocket', 'polling'],
  allowUpgrades: false,
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
  @SubscribeMessage('control')
  // @MessageBody()와 @ConnectedSocket() 데코레이터를 추가합니다.
  handleMessage(
    @MessageBody() payload: ControlMessage,
    @ConnectedSocket() client: Socket,
  ): void {
    console.log(`[${client.id}] 센서 데이터 수신:`, payload);
    console.log(
      `창문: ${payload.w}, 조명: ${payload.light}, 팬: ${payload.fan}, 모드: ${payload.mode}`
    );
    client.broadcast.emit('control', payload);
  }

  @SubscribeMessage('adu-data') // 클라이언트가 보낼 이벤트 이름과 일치해야 함
  handleAdu(
    @MessageBody() payload: AduDataDto, // 👈 string 대신 인터페이스 사용!
    @ConnectedSocket() client: Socket,
  ): void {
    // 2. 이제 payload.temp 처럼 점(.) 찍어서 데이터에 접근 가능합니다.
    console.log(`[${client.id}] 센서 데이터 수신:`, payload);
    console.log(
      `온도: ${payload.temp}, 습도: ${payload.humi}, co2: ${payload.co2}, 조도: ${payload.light}`,
    );
    client.broadcast.emit('adu-data', payload);
  }

  @OnEvent('tempdata')
  handleSerialData(payload: { type: string; value: string }) {
    console.log(`[SocketGateway] Broadcasting serial data: ${payload.value}`);

    this.server.emit('tempdata', payload);
  }

  @SubscribeMessage('python')
  handlePython(
    @MessageBody() payload: any,
    @ConnectedSocket() client: Socket,
  ): void {
    console.log(`[${client.id}] Python 실행 요청:`, payload);
    client.broadcast.emit('python', payload);
  }
  @SubscribeMessage('bluetooth-scan')
  handleBluetoothScan(
    @MessageBody() payload: any,
    @ConnectedSocket() client: Socket,
  ): void {
    console.log(`[${client.id}] 블루투스 스캔 데이터 수신:`, payload);

    // payload 구조 예시:
    // {
    //   deviceId: 'pi-001',
    //   devices: [
    //     { mac: "AA:BB:CC...", rssi: -80, name: "Mi Band" },
    //     ...
    //   ]
    // }

    // 만약 프론트엔드(대시보드)에도 이 데이터를 실시간으로 보여주려면 아래 코드를 사용합니다.
    // client.broadcast.emit('dashboard-bluetooth-data', payload); 
  }
  @Interval(10000)
  handleInterval() {
    const message = {
      type: 'server-time',
      timestamp: new Date().toISOString(),
    };
    this.server.emit('server-time', message);
    this.logger.log('서버 시간 방송');
  }
}
