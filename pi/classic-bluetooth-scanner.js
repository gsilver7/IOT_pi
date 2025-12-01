const { exec } = require('child_process');

const scanClassicBluetooth = (socket) => {
  console.log('🔵 Classic 블루투스 스캐너 시작됨');
  
  setInterval(() => {
    console.log('🔍 hcitool scan 실행 중...');
    
    // timeout을 20초로 늘림
    exec('timeout 20 sudo hcitool scan', { timeout: 25000 }, (error, stdout, stderr) => {
      console.log('=== hcitool 출력 ===');
      console.log('stdout:', stdout);
      
      if (error && error.killed) {
        console.log('⏱️ 타임아웃으로 종료됨 (정상)');
      }

      const lines = stdout.split('\n');
      const devices = lines
        .slice(1)
        .filter(line => line.trim() && !line.includes('Scanning'))
        .map(line => {
          const parts = line.trim().split(/\s+/);
          return { 
            mac: parts[0], 
            name: parts.slice(1).join(' ') || 'Unknown',
            rssi: -50 
          };
        });

      console.log('📡 Classic 장치:', devices);

      if (devices.length > 0) {
        socket.emit('bluetooth-scan', {
          deviceId: 'pi-001',
          devices: devices
        });
      }
    });
  }, 30000); // 30초마다 실행
};

module.exports = { scanClassicBluetooth };