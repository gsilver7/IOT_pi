import { Controller, Post, Body,Get,Logger } from '@nestjs/common';
import { PythonExecutorService } from './python.service';

@Controller('python')
export class PythonController {
  constructor(private readonly pythonExecutor: 
    PythonExecutorService) {}
    private readonly logger = new Logger(PythonController.name);

  @Post('execute2')
  async executePython2(@Body() body: { args?: string[] }) {
    try {
      const result = await this.pythonExecutor.executePythonScript(body.args);
      return {
        success: true,
        output: result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
  @Get('execute')
  async executePython() {
    this.logger.log('python 실행 요청 받음');
    try {
      const result = await this.pythonExecutor.executePythonScript();
      return {
        success: true,
        output: result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
}