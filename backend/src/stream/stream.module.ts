import { Module } from '@nestjs/common';
import { StreamController } from './stream.controller';
import { StreamService } from './stream.service';
import { StreamGateway } from './stream.gateway';

@Module({
  controllers: [StreamController],
  providers: [StreamService, StreamGateway],
  exports: [StreamService],
})
export class StreamModule {}