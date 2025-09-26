import { Injectable } from '@nestjs/common';
import { spawn, ChildProcessWithoutNullStreams } from 'child_process';

// ffmpeg.service.ts
@Injectable()
export class FfmpegService {
  private ffmpegProcess: any = null;

  async startWebcamStream(port: number, ssrc: number) {
    if (this.ffmpegProcess) {
      this.ffmpegProcess.kill();
    }

    const { spawn } = require('child_process');
    
    this.ffmpegProcess = spawn('ffmpeg', [
      '-f', 'v4l2',
      '-i', '/dev/video0',  // 웹캠 장치 경로 확인
      '-c:v', 'libvpx',
      '-b:v', '1000k',      // 비트레이트 설정
      '-r', '30',           // 프레임레이트
      '-s', '640x480',      // 해상도
      '-f', 'rtp',
      '-ssrc', ssrc.toString(),
      `rtp://127.0.0.1:${port}`
    ]);

    this.ffmpegProcess.stdout.on('data', (data) => {
      console.log(`FFmpeg stdout: ${data}`);
    });

    this.ffmpegProcess.stderr.on('data', (data) => {
      console.log(`FFmpeg stderr: ${data}`);
    });

    console.log(`✅ FFmpeg 웹캠 스트림 시작: 포트 ${port}`);
  }

  stopWebcamStream() {
    if (this.ffmpegProcess) {
      this.ffmpegProcess.kill();
      this.ffmpegProcess = null;
    }
  }
}