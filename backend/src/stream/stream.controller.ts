// stream.controller.ts
import { Controller, Get, Res, Logger, Query } from '@nestjs/common';
import { Response } from 'express';
import { StreamService } from './stream.service';

@Controller('stream')
export class StreamController {
  private readonly logger = new Logger(StreamController.name);

  constructor(private readonly streamService: StreamService) {}

  @Get()
  async getMjpegStream(
    @Res() res: Response,
    @Query('client') clientId?: string,
  ): Promise<void> {
    this.logger.log('MJPEG stream requested');
    await this.streamService.startMjpegStream(res, clientId);
  }

  @Get('status')
  getStreamStatus() {
    return {
      status: 'ok',
      timestamp: Date.now(),
      ...this.streamService.getStreamStats(),
    };
  }

  @Get('health')
  getHealth() {
    return {
      status: 'ok',
      timestamp: Date.now(),
      streams: {
        mjpeg: '/stream',
      },
    };
  }

  @Get('test')
  getTestPage(@Res() res: Response): void {
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>NestJS USB Camera Stream</title>
        <style>
            body { 
                margin: 0; 
                padding: 20px; 
                font-family: Arial, sans-serif;
                background: #f0f0f0;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            img { 
                max-width: 100%; 
                height: auto; 
                border: 2px solid #333;
                border-radius: 8px;
                background: #000;
            }
            .status {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 15px;
            }
            .indicator {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: #4CAF50;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
            button {
                padding: 8px 16px;
                background: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                margin-left: 10px;
            }
            button:hover {
                background: #1976D2;
            }
            .nest-badge {
                background: #e0234e;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>
              🎥 NestJS USB 웹캠 스트림 
              <span class="nest-badge">NestJS</span>
            </h1>
            <div class="status">
                <div class="indicator"></div>
                <span>스트리밍 중</span>
                <button onclick="location.reload()">새로고침</button>
                <button onclick="checkStatus()">상태 확인</button>
            </div>
            <img src="/stream" alt="Live Stream" id="streamImg" />
            <div style="margin-top: 15px; font-size: 14px; color: #666;">
                <p><strong>스트림 URL:</strong> <code>/stream</code></p>
                <p><strong>상태 API:</strong> <code>/stream/status</code></p>
                <p><strong>헬스체크:</strong> <code>/stream/health</code></p>
                <p><strong>해상도:</strong> 640x480 @ 15fps</p>
                <p><strong>포맷:</strong> MJPEG over HTTP</p>
                <p><strong>프레임워크:</strong> NestJS</p>
            </div>
            <div id="statusInfo" style="margin-top: 10px; padding: 10px; background: #f5f5f5; border-radius: 4px; display: none;"></div>
        </div>
        
        <script>
            const img = document.getElementById('streamImg');
            const indicator = document.querySelector('.indicator');
            const statusInfo = document.getElementById('statusInfo');
            
            img.onload = () => {
                indicator.style.background = '#4CAF50';
                console.log('NestJS Stream loaded successfully');
            };
            
            img.onerror = () => {
                indicator.style.background = '#F44336';
                console.error('NestJS Stream load failed');
                setTimeout(() => {
                    img.src = '/stream?t=' + Date.now();
                }, 5000);
            };

            async function checkStatus() {
                try {
                    const response = await fetch('/stream/status');
                    const data = await response.json();
                    statusInfo.style.display = 'block';
                    statusInfo.innerHTML = \`
                        <h4>서버 상태</h4>
                        <p><strong>활성 스트림:</strong> \${data.activeStreams}개</p>
                        <p><strong>업타임:</strong> \${Math.round((Date.now() - data.timestamp) / 1000)}초 전 확인</p>
                    \`;
                } catch (error) {
                    statusInfo.style.display = 'block';
                    statusInfo.innerHTML = '<p style="color: red;">상태 확인 실패</p>';
                }
            }
        </script>
    </body>
    </html>
    `;

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  }
}