// src/stream/stream.gateway.ts
import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  ConnectedSocket,
  MessageBody,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import * as fs from 'fs/promises';
import * as path from 'path';

@WebSocketGateway({
  cors: { origin: '*', methods: ['GET', 'POST'] },
  maxHttpBufferSize: 1e8, // 100MB
})
export class StreamGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private connectedClients = new Set<string>();
  private piClient: Socket | null = null; // 라즈베리파이 클라이언트
  private latestFrame: Buffer | null = null;
  private frameCount = 0;

  // 클라이언트가 연결되었을 때
  handleConnection(client: Socket) {
    console.log(`✅ Client connected: ${client.id}`);
    this.connectedClients.add(client.id);

    client.emit('connected', {
      message: 'Connected to webcam stream',
      clientId: client.id,
    });
  }

  // 클라이언트 연결이 끊겼을 때
  handleDisconnect(client: Socket) {
    console.log(`❌ Client disconnected: ${client.id}`);
    this.connectedClients.delete(client.id);

    // 라즈베리파이 클라이언트 연결 끊김
    if (this.piClient?.id === client.id) {
      console.log('🔴 Raspberry Pi disconnected');
      this.piClient = null;
    }
  }

  // 라즈베리파이로부터 웹캠 프레임 수신
  @SubscribeMessage('webcam-frame')
  handleWebcamFrame(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { deviceId: string; frame: string; timestamp: string },
  ) {
    // 라즈베리파이 클라이언트 등록
    if (!this.piClient) {
      this.piClient = client;
      console.log(`📹 Raspberry Pi registered: ${data.deviceId}`);
    }

    try {
      // Base64 -> Buffer 변환
      const frameBuffer = Buffer.from(data.frame, 'base64');
      this.latestFrame = frameBuffer;
      this.frameCount++;

      // 연결된 모든 프론트엔드 클라이언트에게 브로드캐스트
      if (this.connectedClients.size > 0) {
        this.server.emit('frame', {
          data: data.frame, // base64 그대로 전송
          timestamp: Date.now(),
          frameNumber: this.frameCount,
          deviceId: data.deviceId,
        });
      }

      console.log(`📹 Frame ${this.frameCount} broadcasted to ${this.connectedClients.size} clients`);
      
      return { success: true, frameNumber: this.frameCount };
    } catch (error) {
      console.error('🔴 Frame processing error:', error.message);
      return { success: false, error: error.message };
    }
  }

  // 라즈베리파이에 명령 전송
  @SubscribeMessage('control-webcam')
  handleControlWebcam(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { command: 'start' | 'stop' },
  ) {
    if (!this.piClient) {
      client.emit('controlError', {
        message: 'Raspberry Pi not connected',
      });
      return { success: false, error: 'Raspberry Pi not connected' };
    }

    const command = data.command === 'start' ? 'start-webcam' : 'stop-webcam';
    
    this.piClient.emit('command', { command });
    
    console.log(`📡 Command sent to Pi: ${command}`);
    return { success: true, command };
  }

  // 현재 프레임 캡처
  @SubscribeMessage('captureFrame')
  async handleCaptureFrame(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { filename?: string },
  ) {
    try {
      if (!this.latestFrame) {
        client.emit('captureError', {
          message: 'No frame available',
          error: 'Stream not active or no frame captured yet',
        });
        return { success: false, error: 'No frame available' };
      }

      // 저장 경로 설정
      const uploadDir = path.join(process.cwd(), 'uploads', 'captures');
      await fs.mkdir(uploadDir, { recursive: true });

      // 파일명 생성
      const timestamp = Date.now();
      const filename = data?.filename || `capture_${timestamp}.jpg`;
      const filePath = path.join(uploadDir, filename);

      // 파일 저장
      await fs.writeFile(filePath, this.latestFrame);

      // base64로 변환하여 클라이언트로 전송
      const base64Image = this.latestFrame.toString('base64');

      // 성공 응답
      client.emit('captureSuccess', {
        message: 'Frame captured successfully',
        filename,
        path: filePath,
        timestamp,
        imageData: `data:image/jpeg;base64,${base64Image}`,
      });

      console.log(`📸 Captured frame saved: ${filename}`);
      return { success: true, filename };

    } catch (error) {
      console.error('Capture error:', error);
      client.emit('captureError', {
        message: 'Failed to capture frame',
        error: error.message,
      });
      return { success: false, error: error.message };
    }
  }

  // 아두이노 센서 데이터 수신
  @SubscribeMessage('adu-data')
  handleAduData(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { temp: number; humi: number; timestamp: string; deviceId: string },
  ) {
    console.log('📥 Arduino data received:', data);

    // 모든 클라이언트에게 센서 데이터 브로드캐스트
    this.server.emit('sensor-data', data);

    return { success: true, message: 'Sensor data received' };
  }
}