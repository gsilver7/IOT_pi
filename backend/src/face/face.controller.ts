import { Controller, Post, Body, UseGuards, Request, Logger,BadRequestException } from '@nestjs/common';
import { FaceService } from './face.service';
import { AuthGuard } from '@nestjs/passport';
import { StreamGateway } from 'src/stream/stream.gateway';
import { UserService } from 'src/user/user.service';

@Controller('face')
export class FaceController {
  private readonly logger = new Logger(FaceController.name);

  constructor(
    private readonly faceService: FaceService,
    private readonly eventsGateway: StreamGateway,
    private readonly userService: UserService,
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
  @Post('compare')
  @UseGuards(AuthGuard('jwt')) // 로그인한 유저만 가능
  async compareFace(
    @Body('imageData') imageData: string,
    @Request() req,
  ) {
    // 1. JWT에서 유저 ID 추출 (이전 수정사항 반영: userId)
    const userId = req.user.userId;
    
    console.log(`🔍 얼굴 비교 요청 - UserID: ${userId}`);

    // 2. DB에서 저장된 벡터 경로(face 컬럼) 가져오기
    const storedVectorPath = await this.userService.findFaceVectorPath(userId);

    // 3. 예외 처리: 등록된 얼굴이 없는 경우
    if (!storedVectorPath) {
      throw new BadRequestException('등록된 얼굴 정보가 없습니다. 먼저 얼굴을 등록해주세요.');
    }

    console.log(`📂 DB에서 찾은 벡터 경로: ${storedVectorPath}`);

    // 4. 소켓 데이터 구성 (요청하신 조건: id, face, image)
    const socketPayload = {
      id: userId,              // 유저 ID
      face: storedVectorPath,  // DB에서 가져온 벡터 파일 경로 (.pkl)
      image: imageData         // 프론트에서 받은 현재 얼굴 이미지 (Base64)
    };

    // 5. 'compare' 이벤트로 Node.js(Pi)에 전송
    this.eventsGateway.server.emit('compare', socketPayload);
    console.log('📡 compare 이벤트 전송 완료');

    return { message: '얼굴 비교 요청이 전송되었습니다.', success: true };
  }
}