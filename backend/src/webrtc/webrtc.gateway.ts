import { SubscribeMessage, WebSocketGateway, WebSocketServer, OnGatewayConnection, OnGatewayDisconnect } from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';
import * as mediasoup from 'mediasoup';
import { Worker, Router, Transport, Producer, Consumer, RtpCapabilities } from 'mediasoup/node/lib/types';
import { FfmpegService } from '../ffmpeg/ffmpeg.service';

// 클라이언트별 메타데이터를 저장하기 위한 구조체
interface PeerData {
  transport?: Transport;
  producer?: Producer;
  consumer?: Consumer;
  // ... 기타 필요한 정보
}

@WebSocketGateway({ 
  namespace: 'mediasoup', 
  cors: {
    origin: '*', // 개발 편의를 위해 CORS를 와일드카드로 설정합니다.
    methods: ['GET', 'POST'],
    credentials: true,
  },
})
export class MediasoupGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private logger = new Logger('MediasoupGateway');
  private worker: Worker;
  private router: Router;
  
  // 클라이언트별 PeerConnection 데이터 맵
  private peers: Map<string, PeerData> = new Map();
  
  // 현재 활성화된 메인 Producer (웹캠 스트림) ID를 저장합니다.
  private mainProducerId: string | null = null;
  
  // 서버 Producer 초기화 플래그 추가
  private isServerProducerInitialized = false;
  private serverProducer: Producer | null = null;

  constructor(private readonly ffmpegService: FfmpegService) {
    this.createMediasoupWorker();
  }

  // Mediasoup Worker 및 Router 생성
  async createMediasoupWorker() {
    try {
      this.worker = await mediasoup.createWorker({ 
        logLevel: 'warn',    
        rtcMinPort: 40000,
        rtcMaxPort: 49999 
      });
      
      this.router = await this.worker.createRouter({
        mediaCodecs: [
          { kind: 'audio', mimeType: 'audio/opus', clockRate: 48000, channels: 2 },
          { kind: 'video', mimeType: 'video/VP8', clockRate: 90000 },
          { kind: 'video', mimeType: 'video/H264', clockRate: 90000, parameters: { 'packetization-mode': 1 } },
        ],
      });
      
      this.logger.log('Mediasoup Worker 및 Router 생성 완료');
      
      // Worker 종료 시 처리
      this.worker.on('died', () => {
        this.logger.error('Mediasoup Worker가 사망했습니다. 프로세스를 종료합니다.');
        process.exit(1);
      });

      // ✅ Router 생성 완료 (서버 Producer는 첫 클라이언트 연결 시 초기화)
      this.logger.log('Router 준비 완료. 클라이언트 연결 대기 중...');
      
    } catch (error) {
      this.logger.error('Mediasoup Worker 생성 실패:', error);
      process.exit(1);
    }
  }

  // 서버 Producer 초기화 (FFmpeg 웹캠 스트림)
  private async initServerProducer() {
    if (this.isServerProducerInitialized) {
      this.logger.warn('서버 Producer가 이미 초기화되었습니다.');
      return;
    }
    
    try {
      // Plain Transport 생성 (FFmpeg용)
      const plainTransport = await this.router.createPlainTransport({
        listenIp: { ip: '127.0.0.1' },
        rtcpMux: true,
        comedia: true,
      });

      const port = plainTransport.tuple.localPort;
      const ssrc = 12345678;

      this.logger.log(`FFmpeg 스트림을 위한 RTP 포트: ${port}`);

      // FFmpeg 프로세스 시작
      await this.ffmpegService.startWebcamStream(port, ssrc);

      // 서버 Producer 생성 (웹캠 스트림)
      this.serverProducer = await plainTransport.produce({
        kind: 'video',
        rtpParameters: {
          codecs: [{
            mimeType: 'video/VP8',
            payloadType: 96,
            clockRate: 90000,
          }],
          encodings: [{ ssrc: ssrc }],
        },
      });

      this.mainProducerId = this.serverProducer.id;
      this.isServerProducerInitialized = true;
      
      this.logger.log(`✅ 서버 Producer 초기화 완료: ${this.mainProducerId}`);
      
      // Producer 이벤트 핸들러
      this.serverProducer.on('transportclose', () => {
        this.logger.warn('서버 Producer Transport가 닫혔습니다.');
      });

      // 모든 연결된 클라이언트에게 스트림 준비 알림
      this.server.emit('serverStreamReady', { 
        producerId: this.mainProducerId 
      });

    } catch (error) {
      this.logger.error('❌ 서버 Producer 초기화 실패:', error);
      this.isServerProducerInitialized = false;
    }
  }

  handleConnection(client: Socket) {
    this.logger.log(`[${client.id}] 클라이언트 연결: Mediasoup 시그널링 시작`);
    this.peers.set(client.id, {});

    // 첫 번째 클라이언트 연결 시 서버 Producer 초기화
    if (!this.isServerProducerInitialized) {
      this.initServerProducer().catch(error => {
        this.logger.error('서버 Producer 지연 초기화 실패:', error);
      });
    }

    // 이미 서버 스트림이 준비되어 있다면 클라이언트에게 알림
    if (this.isServerProducerInitialized && this.mainProducerId) {
      client.emit('serverStreamReady', { 
        producerId: this.mainProducerId 
      });
    }
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`[${client.id}] 클라이언트 연결 종료`);
    const peerData = this.peers.get(client.id);

    // 연결 종료 시 Transport, Producer, Consumer 정리
    if (peerData?.transport) {
      peerData.transport.close();
    }
    if (peerData?.producer) {
      peerData.producer.close();
      // 클라이언트 Producer가 메인이었다면 서버 Producer로 복원
      if (this.mainProducerId === peerData.producer.id && this.serverProducer) {
        this.mainProducerId = this.serverProducer.id;
        this.server.emit('streamChanged', { 
          producerId: this.mainProducerId 
        });
      }
    }
    if (peerData?.consumer) {
      peerData.consumer.close();
    }
    this.peers.delete(client.id);
  }

  // 1. 클라이언트의 RTP Capabilities 요청 처리
  @SubscribeMessage('getRouterRtpCapabilities')
  handleGetRtpCapabilities(client: Socket): RtpCapabilities {
    this.logger.log(`[${client.id}] Router RTP Capabilities 전송`);
    const rtpCapabilities = this.router.rtpCapabilities;
    client.emit('routerRtpCapabilities', rtpCapabilities); 
    return rtpCapabilities;
  }

  // 2. Transport 생성 요청 처리
  @SubscribeMessage('startTransport')
  async handleCreateTransport(client: Socket, { forceTcp, producing, consuming }) {
    try {
      // 클라이언트 IP 확인
      const clientIP = client.handshake.address;
      this.logger.log(`클라이언트 IP: ${clientIP}`);
      
      // 로컬 네트워크인지 확인
      const isLocalNetwork = clientIP.startsWith('192.168.') || 
                            clientIP.startsWith('10.') || 
                            clientIP.startsWith('172.16.') ||
                            clientIP === '127.0.0.1' ||
                            clientIP === '::1' ||
                            clientIP === '::ffff:127.0.0.1';

      let announcedIp;
      if (isLocalNetwork) {
        // 로컬 네트워크면 라즈베리 파이의 로컬 IP 사용
        announcedIp = this.getLocalIP();
      } else {
        // 외부 네트워크면 공인 IP 사용
        announcedIp = process.env.ANNOUNCED_IP || '1.229.202.198';
      }

      this.logger.log(`사용할 announcedIp: ${announcedIp}`);

      const transport = await this.router.createWebRtcTransport({
        listenIps: [{ ip: '0.0.0.0', announcedIp }],
        enableTcp: true,
        enableUdp: true,
        preferTcp: forceTcp,
        appData: { clientId: client.id, producing, consuming },
      });

      // 생성된 Transport를 클라이언트 데이터에 저장
      this.peers.get(client.id).transport = transport;

      this.logger.log(`[${client.id}] Transport 생성: ${transport.id} (Producing: ${producing}, Consuming: ${consuming})`);
      
      const response = {
        id: transport.id,
        iceParameters: transport.iceParameters,
        iceCandidates: transport.iceCandidates,
        dtlsParameters: transport.dtlsParameters,
        sctpParameters: transport.sctpParameters,
      };

      client.emit('transportCreated', response);
      return response;
      
    } catch (error) {
      this.logger.error(`[${client.id}] Transport 생성 실패:`, error.message);
      return { error: error.message };
    }
  }

  private getLocalIP(): string {
    const interfaces = require('os').networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal && iface.address.startsWith('192.168.')) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }

  // 3. Transport 연결 (DTLS 연결 요청 처리)
  @SubscribeMessage('connectWebRtcTransport')
  async handleConnectTransport(client: Socket, { transportId, dtlsParameters }) {
    this.logger.log(`[${client.id}] Transport 연결 요청. ID: ${transportId}`);

    const transport = this.peers.get(client.id)?.transport;

    if (!transport || transport.id !== transportId) {
      const errorMessage = `[${client.id}] ID에 해당하는 Transport를 찾을 수 없음: ${transportId}`;
      this.logger.error(errorMessage);
      return { error: errorMessage };
    }

    try {
      await transport.connect({ dtlsParameters: dtlsParameters });
      this.logger.log(`[${client.id}] Transport 연결 성공: ${transport.id}`);
      return { connected: true };

    } catch (error) {
      const errorMessage = `[${client.id}] Transport 연결 실패: ${error.message}`;
      this.logger.error(errorMessage);
      return { error: errorMessage };
    }
  }

  // 4. Producer 생성 (클라이언트가 스트리밍하는 경우)
  @SubscribeMessage('produce')
  async handleProduce(client: Socket, { transportId, kind, rtpParameters }) {
    const transport = this.peers.get(client.id)?.transport;
    
    if (!transport || transport.id !== transportId) {
      return { error: 'Transport not found' };
    }

    try {
      // 클라이언트 Producer 생성
      const producer = await transport.produce({
        kind,
        rtpParameters,
      });
      
      this.peers.get(client.id).producer = producer;
      
      // 클라이언트 비디오 스트림을 메인으로 설정
      if (kind === 'video') {
        this.mainProducerId = producer.id;
        this.server.emit('newClientStream', { 
          producerId: producer.id,
          clientId: client.id 
        });
        this.logger.log(`[${client.id}] 메인 Producer 변경: ${producer.id}`);
      }

      this.logger.log(`[${client.id}] 클라이언트 Producer 생성: ${producer.id}`);
      return { id: producer.id };
      
    } catch (error) {
      this.logger.error(`[${client.id}] Producer 생성 실패:`, error.message);
      return { error: error.message };
    }
  }

  // 5. Consumer 생성 (클라이언트가 서버 스트림을 수신)
  @SubscribeMessage('consume')
  async handleConsume(client: Socket, { consumerTransportId, rtpCapabilities }) {
    const consumerTransport = this.peers.get(client.id)?.transport;
    
    if (!consumerTransport) {
      this.logger.error(`[${client.id}] Consumer Transport를 찾을 수 없음`);
      return { error: 'Transport not found' };
    }

    // 메인 Producer가 없으면 에러 반환
    if (!this.mainProducerId) {
      this.logger.warn(`[${client.id}] 소비할 메인 Producer가 현재 없습니다.`);
      return { error: 'No main stream available' };
    }

    // RTP Capabilities 체크
    if (!this.router.canConsume({
      producerId: this.mainProducerId,
      rtpCapabilities,
    })) {
      this.logger.error(`[${client.id}] 클라이언트가 Producer를 consume할 수 없음`);
      return { error: 'Cannot consume' };
    }

    try {
      // Producer ID를 사용하여 Consumer 생성
      const consumer = await consumerTransport.consume({
        producerId: this.mainProducerId,
        rtpCapabilities: rtpCapabilities,
        paused: true, // 초기에는 일시 정지 상태로 생성
      });
      
      this.peers.get(client.id).consumer = consumer;
      this.logger.log(`[${client.id}] Consumer 생성 완료: ${consumer.id}`);

      // Consumer 이벤트 핸들러
      consumer.on('producerclose', () => {
        this.logger.log(`[${client.id}] Producer가 닫혀 Consumer ${consumer.id} 종료`);
        consumer.close();
        const peerData = this.peers.get(client.id);
        if (peerData) {
          peerData.consumer = null;
        }
        // 클라이언트에게 스트림 종료 알림
        client.emit('consumerClosed', { consumerId: consumer.id });
      });

      consumer.on('transportclose', () => {
        this.logger.log(`[${client.id}] Consumer Transport가 닫혔습니다: ${consumer.id}`);
      });

      return {
        id: consumer.id,
        producerId: consumer.producerId,
        kind: consumer.kind,
        rtpParameters: consumer.rtpParameters,
        type: consumer.type,
        paused: consumer.paused,
      };

    } catch (error) {
      this.logger.error(`[${client.id}] Consumer 생성 실패:`, error.message);
      return { error: error.message };
    }
  }

  // 6. Consumer 재개 (클라이언트 요청 시 영상 재생 시작)
  @SubscribeMessage('resume')
  async handleResume(client: Socket, { consumerId }) {
    const consumer = this.peers.get(client.id)?.consumer;
    
    if (!consumer) {
      this.logger.error(`[${client.id}] Consumer를 찾을 수 없음`);
      return { error: 'Consumer not found' };
    }

    if (consumerId && consumer.id !== consumerId) {
      this.logger.error(`[${client.id}] Consumer ID 불일치: ${consumerId}`);
      return { error: 'Consumer ID mismatch' };
    }

    try {
      await consumer.resume();
      this.logger.log(`[${client.id}] Consumer ${consumer.id} 재개`);
      return { resumed: true };
    } catch (error) {
      this.logger.error(`[${client.id}] Consumer 재개 실패:`, error.message);
      return { error: error.message };
    }
  }

  // 7. Consumer 일시 정지
  @SubscribeMessage('pause')
  async handlePause(client: Socket, { consumerId }) {
    const consumer = this.peers.get(client.id)?.consumer;
    
    if (!consumer) {
      this.logger.error(`[${client.id}] Consumer를 찾을 수 없음`);
      return { error: 'Consumer not found' };
    }

    try {
      await consumer.pause();
      this.logger.log(`[${client.id}] Consumer ${consumer.id} 일시정지`);
      return { paused: true };
    } catch (error) {
      this.logger.error(`[${client.id}] Consumer 일시정지 실패:`, error.message);
      return { error: error.message };
    }
  }

  // 8. 서버 상태 확인
  @SubscribeMessage('getServerStatus')
  handleGetServerStatus(client: Socket) {
    const status = {
      workerAlive: this.worker && !this.worker.closed,
      routerAlive: this.router && !this.router.closed,
      serverProducerReady: this.isServerProducerInitialized,
      mainProducerId: this.mainProducerId,
      connectedClients: this.peers.size,
    };

    this.logger.log(`[${client.id}] 서버 상태 요청:`, status);
    return status;
  }

  // 서버 종료 시 정리
  async onApplicationShutdown(signal?: string) {
    this.logger.log(`애플리케이션 종료 신호 수신: ${signal}`);
    
    // FFmpeg 프로세스 종료
    this.ffmpegService.stopWebcamStream();
    
    // 모든 클라이언트 연결 정리
    for (const [clientId, peerData] of this.peers.entries()) {
      if (peerData.transport) peerData.transport.close();
      if (peerData.producer) peerData.producer.close();
      if (peerData.consumer) peerData.consumer.close();
    }
    this.peers.clear();

    // Mediasoup 리소스 정리
    if (this.serverProducer) {
      this.serverProducer.close();
    }
    if (this.router) {
      this.router.close();
    }
    if (this.worker) {
      this.worker.close();
    }

    this.logger.log('Mediasoup 리소스 정리 완료');
  }
}