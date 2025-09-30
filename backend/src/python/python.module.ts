import { Module } from '@nestjs/common';
import {PythonExecutorService} from './python.service';
import {PythonController} from './python.controller';

@Module({
  imports: [],
  controllers: [PythonController],
  providers: [PythonExecutorService],
})
export class PythonModule {}
