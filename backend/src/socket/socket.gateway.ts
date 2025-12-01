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
import { User } from '../user/user.entity'; // User 엔티티 import 경로에 맞게 수정
import { Repository, Not, IsNull } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

interface AduDataDto {
  temp: string;
  humi: string;
  co2: string;
  light: string;
  timestamp: string;
  deviceId: string;
}

interface ControlMessage {
  glight: number;
  hlight: number;
  w: number;
  fan: number;
  hum: number;
  hit: number;
  door: number;
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

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}


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
      `창문: ${payload.w}, 조명: ${payload.hlight}, 팬: ${payload.fan}, 모드: ${payload.mode}`
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
  async handleBluetoothScan(
    @MessageBody() payload: any,
    @ConnectedSocket() client: Socket,
  ): Promise<void> {
    console.log(`[${client.id}] 블루투스 스캔 데이터 수신:`, payload);

    // payload 구조:
    // {
    //   deviceId: 'pi-001',
    //   devices: [
    //     { mac: "AA:BB:CC:DD:EE:FF", rssi: -80, name: "Mi Band" },
    //   ]
    // }

    try {
      // 1. 스캔된 MAC 주소 추출
      const scannedMacs = payload.devices?.map(device => device.mac) || [];
      
      if (scannedMacs.length === 0) {
        console.log('스캔된 블루투스 장치가 없습니다.');
        return;
      }

      console.log('스캔된 MAC 주소들:', scannedMacs);

      // 2. 데이터베이스에서 모든 사용자의 블루투스 MAC 주소 조회
      const users = await this.userRepository.find({
        where: {
          bluetooth: Not(IsNull()), // bluetooth 칼럼이 null이 아닌 것만
        },
        select: ['id', 'bluetooth'], // 필요한 칼럼만 조회
      });

      // 3. DB의 MAC 주소들 추출 (중복 제거)
      const dbMacs = users
        .map(user => user.bluetooth)
        .filter(mac => mac && mac.trim() !== '');

      console.log('DB에 저장된 MAC 주소들:', dbMacs);

      // 4. 겹치는 MAC 주소 찾기
      const matchedMacs = scannedMacs.filter(scannedMac => 
        dbMacs.some(dbMac => 
          dbMac.toUpperCase() === scannedMac.toUpperCase()
        )
      );

      // 5. 겹치는 MAC 주소가 있으면 프론트로 전송
      if (matchedMacs.length > 0) {
        console.log('✅ 일치하는 MAC 주소 발견:', matchedMacs);
        
        // 일치하는 MAC 주소와 해당 장치 정보를 함께 전송
        const matchedDevices = payload.devices.filter(device =>
          matchedMacs.some(mac => 
            mac.toUpperCase() === device.mac.toUpperCase()
          )
        );

        // 프론트엔드로 소켓 전송
        this.server.emit('mac', {
          matched: true,
          macs: matchedMacs,
          devices: matchedDevices,
          timestamp: new Date().toISOString(),
        });

        // 또는 특정 클라이언트에만 전송하려면:
        // client.emit('mac', { ... });
      } else {
        console.log('❌ 일치하는 MAC 주소 없음');
        this.server.emit('mac', {
          matched: false,
          timestamp: new Date().toISOString(),
        });
      }

    } catch (error) {
      console.error('블루투스 스캔 처리 중 오류:', error);
      client.emit('error', {
        message: '블루투스 데이터 처리 실패',
        error: error.message,
      });
    }
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
