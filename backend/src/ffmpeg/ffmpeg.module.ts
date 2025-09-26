// ffmpeg.module.ts
import { Module } from '@nestjs/common';
import { FfmpegService } from './ffmpeg.service';

@Module({
  providers: [FfmpegService],
  exports: [FfmpegService], // 외부 모듈에서 사용 가능하도록 export
})
export class FfmpegModule {}
