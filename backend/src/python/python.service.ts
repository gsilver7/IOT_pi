import { Injectable } from '@nestjs/common';
import { spawn } from 'child_process';

@Injectable()
export class PythonExecutorService {
  private readonly venvPath = '/home/rlaaudwns/web/backend/python';
  private readonly scriptPath = '/home/rlaaudwns/web/backend/src/python/cv.py';

  executePythonScript(args?: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const pythonPath = process.platform === 'win32'
        ? `${this.venvPath}\\Scripts\\python.exe`
        : `${this.venvPath}/bin/python`;

      const scriptArgs = args || [];
      const pythonProcess = spawn(pythonPath, [this.scriptPath, ...scriptArgs]);

      let stdout = '';
      let stderr = '';

      pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
        console.log('Python output:', data.toString());
      });

      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
        console.error('Python error:', data.toString());
      });

      pythonProcess.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`Python 프로세스가 코드 ${code}로 종료됨: ${stderr}`));
        } else {
          resolve(stdout);
        }
      });

      pythonProcess.on('error', (error) => {
        reject(new Error(`Python 실행 실패: ${error.message}`));
      });
    });
  }
}