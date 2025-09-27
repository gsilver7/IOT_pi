// stream.service.ts
import { Injectable, Logger } from '@nestjs/common';
import * as ffmpeg from 'fluent-ffmpeg';
import { Response } from 'express';

@Injectable()
export class StreamService {
  private readonly logger = new Logger(StreamService.name);
  private activeStreams = new Map<string, any>();

  async startMjpegStream(res: Response, clientId?: string): Promise<void> {
    const streamId = clientId || `stream_${Date.now()}`;
    
    this.logger.log(`Starting MJPEG stream for client: ${streamId}`);

    // MJPEG 멀티파트 헤더 설정
    res.writeHead(200, {
      'Content-Type': 'multipart/x-mixed-replace; boundary=--myboundary',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // FFmpeg 명령어 구성
    const command = ffmpeg('/dev/video0')
      .inputOptions(['-re', '-f', 'v4l2'])
      .size('640x480')
      .fps(15)
      .videoCodec('mjpeg')
      .outputOptions([
        '-f', 'mjpeg',
        '-q:v', '3',
        '-huffman', 'optimal',
      ]);

    // 이벤트 리스너 설정
    command
      .on('start', (cmdline) => {
        this.logger.log(`FFmpeg started for ${streamId}: ${cmdline}`);
      })
      .on('error', (err) => {
        this.logger.error(`FFmpeg error for ${streamId}: ${err.message}`);
        this.cleanup(streamId);
        if (!res.headersSent) {
          res.end();
        }
      })
      .on('end', () => {
        this.logger.log(`FFmpeg stream ended for ${streamId}`);
        this.cleanup(streamId);
        if (!res.headersSent) {
          res.end();
        }
      });

    const stream = command.pipe();
    let frameCount = 0;

    // 스트림 데이터 처리
    stream.on('data', (chunk: Buffer) => {
      frameCount++;
      if (frameCount % 100 === 0) {
        this.logger.log(`Streamed ${frameCount} frames for ${streamId}`);
      }

      try {
        if (!res.destroyed && !res.headersSent) {
          res.write('--myboundary\r\n');
          res.write('Content-Type: image/jpeg\r\n');
          res.write(`Content-Length: ${chunk.length}\r\n\r\n`);
          res.write(chunk);
          res.write('\r\n');
        }
      } catch (writeError) {
        this.logger.error(`Write error for ${streamId}: ${writeError.message}`);
        command.kill('SIGKILL');
        this.cleanup(streamId);
      }
    });

    stream.on('error', (err) => {
      this.logger.error(`Stream error for ${streamId}: ${err.message}`);
      this.cleanup(streamId);
      if (!res.headersSent) {
        res.end();
      }
    });

    // 스트림 정보 저장
    this.activeStreams.set(streamId, {
      command,
      stream,
      startTime: Date.now(),
      frameCount: 0,
    });

    // 클라이언트 연결 종료 감지
    res.on('close', () => {
      this.logger.log(`Client ${streamId} disconnected`);
      this.cleanup(streamId);
    });

    res.on('error', (err) => {
      this.logger.error(`Response error for ${streamId}: ${err.message}`);
      this.cleanup(streamId);
    });
  }

  private cleanup(streamId: string): void {
    const streamInfo = this.activeStreams.get(streamId);
    if (streamInfo) {
      try {
        if (streamInfo.command) {
          streamInfo.command.kill('SIGKILL');
        }
        this.activeStreams.delete(streamId);
        this.logger.log(`Cleaned up stream ${streamId}`);
      } catch (error) {
        this.logger.error(`Error during cleanup for ${streamId}: ${error.message}`);
      }
    }
  }

  getStreamStats() {
    const stats = [];
    for (const [streamId, info] of this.activeStreams.entries()) {
      stats.push({
        streamId,
        startTime: info.startTime,
        duration: Date.now() - info.startTime,
        frameCount: info.frameCount,
      });
    }
    return {
      activeStreams: this.activeStreams.size,
      streams: stats,
    };
  }

  stopAllStreams(): void {
    this.logger.log('Stopping all active streams');
    for (const streamId of this.activeStreams.keys()) {
      this.cleanup(streamId);
    }
  }
}