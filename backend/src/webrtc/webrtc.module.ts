import { Module } from '@nestjs/common';
import { MediasoupGateway } from './webrtc.gateway';
import { FfmpegModule } from '../ffmpeg/ffmpeg.module';

@Module({
  imports : [FfmpegModule],
  providers: [MediasoupGateway,], // WebRTC 관련 
  exports: []
  // Provider들을 이 모듈에서 관리
})
export class WebrtcModule {}

