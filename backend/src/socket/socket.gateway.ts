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
import { User } from '../user/user.entity';
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

// ✅ 블루투스 DTO 추가
interface BluetoothDto {
  device: string;
  command: string;
  key: string;
  value: string;
}

// ✅ 제어 상태 DTO 추가
interface ControlStateDto {
  hlight: number;
  glight: number;
  win: number;
  fan: number;
  hit: number;
  hum: number;
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

  // ✅ 전체 제어 상태 저장
  private controlState: ControlStateDto = {
    hlight: 0,
    glight: 0,
    win: 0,
    fan: 0,
    hit: 0,
    hum: 0,
    door: 0,
    mode: 'sudong',
  };

  handleConnection(client: Socket) {
    console.log(`Client connected: ${client.id}`);
    // ✅ 새 클라이언트에게 현재 상태 전송
    client.emit('control-state', this.controlState);
  }

  handleDisconnect(client: Socket) {
    console.log(`Client disconnected: ${client.id}`);
  }

  // ==================== 블루투스 명령 처리 (새로 추가) ====================

  @SubscribeMessage('bluetooth')
  handleBluetooth(
    @MessageBody() data: BluetoothDto,
    @ConnectedSocket() client: Socket,
  ): void {
    this.logger.log(`📱 [${client.id}] bluetooth 수신:`, data);

    const { key, value } = data;
    const trimmedValue = value?.trim();

    // ✅ 상태 업데이트
    const updated = this.updateControlState(key, trimmedValue);

    if (updated) {
      this.logger.log(`✅ 상태 업데이트:`, this.controlState);

      // ✅ 전체 상태를 모든 클라이언트에게 브로드캐스트
      this.server.emit('control-state', this.controlState);
    } else {
      this.logger.warn(
        `⚠️ 상태 업데이트 실패 - key: ${key}, value: ${trimmedValue}`,
      );
    }
  }

  // ✅ 상태 업데이트 로직
  private updateControlState(key: string, value: string): boolean {
    switch (key) {
      case 'MODE':
        return this.updateMode(value);
      case 'WIN':
        return this.updateOnOff('win', value);
      case 'FAN':
        return this.updateOnOff('fan', value);
      case 'HUMID':
        return this.updateOnOff('hum', value);
      case 'HEAT':
        return this.updateOnOff('hit', value);
      case 'LIGHT':
        return this.updateOnOff('glight', value);
      case 'DOOR':
        return this.updateOnOff('door', value);
      default:
        this.logger.warn(`⚠️ 알 수 없는 key: ${key}`);
        return false;
    }
  }

  private updateMode(value: string): boolean {
    const modeMap: { [key: string]: string } = {
      '0': 'sudong',
      '1': 'in',
      '2': 'zzz',
      '3': 'out',
    };

    const mode = modeMap[value];
    if (mode) {
      this.controlState.mode = mode;
      return true;
    }

    this.logger.warn(`⚠️ 잘못된 MODE 값: ${value}`);
    return false;
  }

  private updateOnOff(
    field: keyof ControlStateDto,
    value: string,
  ): boolean {
    if (value === '0') {
      (this.controlState as any)[field] = 0;
      return true;
    } else if (value === '1') {
      (this.controlState as any)[field] = 1;
      return true;
    }

    this.logger.warn(`⚠️ 잘못된 ${field} 값: ${value}`);
    return false;
  }

  // ✅ 현재 상태 조회
  @SubscribeMessage('get-state')
  handleGetState(@ConnectedSocket() client: Socket): ControlStateDto {
    this.logger.log(`📊 [${client.id}] get-state 요청`);
    return this.controlState;
  }

  // ==================== 기존 코드 ====================

  @SubscribeMessage('control')
  handleMessage(
    @MessageBody() payload: ControlMessage,
    @ConnectedSocket() client: Socket,
  ): void {
    console.log(`[${client.id}] 센서 데이터 수신:`, payload);
    console.log(
      `창문: ${payload.w}, 조명: ${payload.hlight}, 팬: ${payload.fan}, 모드: ${payload.mode}`,
    );

    // ✅ 프론트에서 받은 제어 상태로 전체 상태 업데이트
    if (payload.mode) this.controlState.mode = payload.mode;
    if (payload.hlight !== undefined) this.controlState.hlight = payload.hlight;
    if (payload.glight !== undefined) this.controlState.glight = payload.glight;
    if (payload.w !== undefined) this.controlState.win = payload.w;
    if (payload.fan !== undefined) this.controlState.fan = payload.fan;
    if (payload.hum !== undefined) this.controlState.hum = payload.hum;
    if (payload.hit !== undefined) this.controlState.hit = payload.hit;
    if (payload.door !== undefined) this.controlState.door = payload.door;

    this.logger.log(`✅ control로 상태 업데이트:`, this.controlState);

    client.broadcast.emit('control', payload);
    // ✅ 업데이트된 전체 상태도 브로드캐스트
    this.server.emit('control-state', this.controlState);
  }

  @SubscribeMessage('adu-data')
  handleAdu(
    @MessageBody() payload: AduDataDto,
    @ConnectedSocket() client: Socket,
  ): void {
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

    try {
      const scannedMacs = payload.devices?.map((device) => device.mac) || [];

      if (scannedMacs.length === 0) {
        console.log('스캔된 블루투스 장치가 없습니다.');
        return;
      }

      console.log('스캔된 MAC 주소들:', scannedMacs);

      const users = await this.userRepository.find({
        where: {
          bluetooth: Not(IsNull()),
        },
        select: ['id', 'bluetooth'],
      });

      const dbMacs = users
        .map((user) => user.bluetooth)
        .filter((mac) => mac && mac.trim() !== '');

      console.log('DB에 저장된 MAC 주소들:', dbMacs);

      const matchedMacs = scannedMacs.filter((scannedMac) =>
        dbMacs.some(
          (dbMac) => dbMac.toUpperCase() === scannedMac.toUpperCase(),
        ),
      );

      if (matchedMacs.length > 0) {
        console.log('✅ 일치하는 MAC 주소 발견:', matchedMacs);

        const matchedDevices = payload.devices.filter((device) =>
          matchedMacs.some(
            (mac) => mac.toUpperCase() === device.mac.toUpperCase(),
          ),
        );

        this.server.emit('mac', {
          matched: true,
          macs: matchedMacs,
          devices: matchedDevices,
          users: users.filter((user) =>
            matchedMacs.some(
              (mac) => mac.toUpperCase() === user.bluetooth.toUpperCase(),
            ),
          ),
          timestamp: new Date().toISOString(),
        });
      } else {
        console.log('❌ 일치하는 MAC 주소 없음');
        this.server.emit('mac', {
          matched: false,
          macs: [],
          devices: [],
          users: [],
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