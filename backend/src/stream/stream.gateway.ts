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
import * as ffmpeg from 'fluent-ffmpeg';
import { FfmpegCommand } from 'fluent-ffmpeg';
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
  private streamCommand: FfmpegCommand | null = null;
  private isStreaming = false;
  private latestFrame: Buffer | null = null; // 최신 프레임 저장

  // 클라이언트가 연결되었을 때
  handleConnection(client: Socket) {
    console.log(`✅ Client connected: ${client.id}`);
    this.connectedClients.add(client.id);

    // 첫 클라이언트 연결 시 스트림 시작
    if (this.connectedClients.size === 1) {
      this.startWebcamStream();
    }

    client.emit('connected', {
      message: 'Connected to webcam stream',
      clientId: client.id,
    });
  }

  // 클라이언트 연결이 끊겼을 때
  handleDisconnect(client: Socket) {
    console.log(`❌ Client disconnected: ${client.id}`);
    this.connectedClients.delete(client.id);

    // 모든 클라이언트가 나가면 스트림 중지
    if (this.connectedClients.size === 0) {
      this.stopWebcamStream();
    }
  }

  // FFmpeg 스트림 시작
  private startWebcamStream() {
    if (this.isStreaming) {
      console.log('Stream already running');
      return;
    }
    console.log('Starting webcam stream...');
    this.isStreaming = true;

    this.streamCommand = ffmpeg('/dev/video0')
      .inputOptions(['-re', '-f', 'v4l2'])
      .size('640x480')
      .fps(15)
      .videoCodec('mjpeg')
      .outputOptions(['-f', 'image2pipe', '-vcodec', 'mjpeg', '-q:v', '5', '-huffman', 'optimal']);

    this.streamCommand
      .on('start', (cmdline) => console.log('FFmpeg started:', cmdline))
      .on('error', (err) => {
        console.error('FFmpeg error:', err.message);
        this.stopWebcamStream();
      })
      .on('end', () => {
        console.log('FFmpeg stream ended');
        this.stopWebcamStream();
      });

    const stream = this.streamCommand.pipe();
    let buffer = Buffer.alloc(0);
    let frameCount = 0;

    stream.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      let startIdx = buffer.indexOf(Buffer.from([0xFF, 0xD8]));
      let endIdx = buffer.indexOf(Buffer.from([0xFF, 0xD9]));

      while (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
        const frame = buffer.slice(startIdx, endIdx + 2);
        buffer = buffer.slice(endIdx + 2);
        frameCount++;

        this.latestFrame = frame;

        if (this.connectedClients.size > 0) {
          const base64Frame = frame.toString('base64');
          this.server.emit('frame', {
            data: base64Frame,
            timestamp: Date.now(),
            frameNumber: frameCount,
          });
        }

        startIdx = buffer.indexOf(Buffer.from([0xFF, 0xD8]));
        endIdx = buffer.indexOf(Buffer.from([0xFF, 0xD9]));
      }
    });

    stream.on('error', (err) => {
      console.error('Stream error:', err.message);
      this.stopWebcamStream();
    });
  }

  // FFmpeg 스트림 중지
  private stopWebcamStream() {
    if (this.streamCommand) {
      console.log('Stopping webcam stream...');
      this.streamCommand.kill('SIGKILL');
      this.streamCommand = null;
    }
    this.isStreaming = false;
  }

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

      // 성공 응답 (파일 정보 + 이미지 데이터)
      client.emit('captureSuccess', {
        message: 'Frame captured successfully',
        filename,
        path: filePath,
        timestamp,
        imageData: `data:image/jpeg;base64,${base64Image}`, // 프론트에서 바로 사용 가능
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

}