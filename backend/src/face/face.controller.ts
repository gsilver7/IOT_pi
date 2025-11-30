import { Controller, Post, Body, UseGuards, Request } from '@nestjs/common';
import { FaceService } from './face.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('api/face')
export class FaceController {
  constructor(private readonly faceService: FaceService) {}

  @Post('register')
   @UseGuards(AuthGuard('jwt'))
  async registerFace(
    @Body('imageData') imageData: string,
    @Request() req,
  ) {
    const userId = req.user.id; // JWT에서 유저 ID 추출
    return this.faceService.registerFace(userId, imageData);
  }
}