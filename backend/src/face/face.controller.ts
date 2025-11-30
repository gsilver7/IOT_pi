import { Controller, Post, Body, UseGuards, Request, Logger } from '@nestjs/common';
import { FaceService } from './face.service';
import { AuthGuard } from '@nestjs/passport';
import { StreamGateway } from 'src/stream/stream.gateway';


@Controller('face')
export class FaceController {
  private readonly logger = new Logger(FaceController.name);

  constructor(
    private readonly faceService: FaceService,
    private readonly eventsGateway: StreamGateway,
  ) {}

  @Post('register')
  @UseGuards(AuthGuard('jwt'))
  async registerFace(
    @Body('imageData') imageData: string,
    @Request() req,
  ) {
    try {
      this.logger.log('=== Face Register 시작 ===');
      this.logger.log(`User ID: ${req.user?.id}`);
      this.logger.log(`ImageData 존재 여부: ${!!imageData}`);

      const userId = req.user.userId; // JWT에서 유저 ID 추출
      console.log(userId);
      const data = {
        image: imageData, // 프론트에서 받은 Base64 문자열 (data:image/jpeg;base64,...)
        userId: userId,   // 파일명 저장용 ID
        // scriptPath: '/path/to/script.py', // (선택) 필요하면 경로 지정
      };
      this.eventsGateway.server.emit('python', data);
      console.log("python");

      const result = await this.faceService.registerFace(userId, imageData);
      this.logger.log('Face 등록 완료');
      return result;
    } catch (error) {
      this.logger.error('Face Register 에러:', error.message);
      this.logger.error(error.stack);
      throw error;
    }
  }
}