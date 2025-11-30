// src/stream/stream.module.ts
import { Module } from '@nestjs/common';
import { StreamGateway } from './stream.gateway';
import { StreamController } from './stream.controller';
import { UserModule } from 'src/user/user.module';

@Module({
  imports:[UserModule],
  providers: [StreamGateway],
  controllers: [StreamController],
  exports:[StreamGateway],
})
export class StreamModule {}