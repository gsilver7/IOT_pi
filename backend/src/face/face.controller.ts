import { Controller, Post, Body, UseGuards, Request } from '@nestjs/common';
import { FaceService } from './face.service';
import { AuthGuard } from '@nestjs/passport';
import { StreamGateway } from 'src/stream/stream.gateway';


@Controller('face')
export class FaceController {
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
    const userId = req.user.id; // JWT에서 유저 ID 추출

    this.eventsGateway.server.emit('python', 
      "python"
    );
    console.log("python");

    return this.faceService.registerFace(userId, imageData);
  }
}