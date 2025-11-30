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

      const userId = req.user.id; // JWT에서 유저 ID 추출

      this.eventsGateway.server.emit('python', 
        "python"
      );
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