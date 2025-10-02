// src/stream/stream.controller.ts
import { Controller, Get } from '@nestjs/common';

@Controller('stream')
export class StreamController {
  @Get()
  getStreamPage(): string {
    // 기존 코드의 HTML 부분을 그대로 반환합니다.
    return `
<!DOCTYPE html>
<html>
<body>
    <div class="container">
        <canvas id="streamCanvas" width="640" height="480"></canvas>
    </div>
    
    <script src="/socket.io/socket.io.js"></script>
    <script>
        const canvas = document.getElementById('streamCanvas');
        const ctx = canvas.getContext('2d');
        let socket;
        
        function connect() {
            // NestJS 서버의 웹소켓 네임스페이스에 연결합니다.
            socket = io('/', {
                transports: ['websocket', 'polling']
            });
            
            socket.on('connect', () => console.log('서버에 연결되었습니다.'));
            
            socket.on('frame', (data) => {
                const img = new Image();
                img.onload = () => {
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                };
                img.src = 'data:image/jpeg;base64,' + data.data;
            });
            
            socket.on('disconnect', () => console.log('서버와의 연결이 끊겼습니다.'));
            socket.on('connect_error', (error) => console.error('연결 오류:', error));
        }
        
        connect();
        
        window.addEventListener('beforeunload', () => {
            if (socket) {
                socket.disconnect();
            }
        });
    </script>
</body>
</html>
    `;
  }
}