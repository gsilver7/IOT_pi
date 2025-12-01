// unified-bluetooth-scanner.js
const { exec } = require('child_process');
const noble = require('@abandonware/noble');

let socketClient = null;
let foundDevices = {}; // BLE 장치 저장
let isScanning = false;
let scanInterval = null;
let classicScanInterval = null;

// =========================================================
// [1] BLE 스캐너 관련 함수들
// =========================================================

const startBleScan = async () => {
  if (isScanning) return;
  try {
    await noble.startScanningAsync([], true);
    isScanning = true;
    console.log('✅ BLE 스캔 시작됨');
  } catch (e) {
    console.error('🔴 BLE 스캔 시작 실패:', e);
  }
};

const initBleScanner = () => {
  console.log('🔵 BLE 스캐너 초기화 중...');

  noble.on('stateChange', async (state) => {
    if (state === 'poweredOn') {
      console.log('🔵 블루투스 어댑터 켜짐 (poweredOn)');
      startBleScan();
    } else {
      console.log('🔴 블루투스 꺼짐 (State:', state, ')');
      noble.stopScanning();
      isScanning = false;
    }
  });

  noble.on('discover', (peripheral) => {
    const mac = peripheral.address;
    foundDevices[mac] = {
      mac: mac,
      name: peripheral.advertisement.localName || 'Unknown',
      rssi: peripheral.rssi,
      type: 'BLE',
      lastSeen: Date.now()
    };
  });
};

// =========================================================
// [2] Classic 블루투스 스캐너 함수
// =========================================================

const scanClassicBluetooth = () => {
  console.log('🔵 Classic 블루투스 스캐너 시작됨');
  
  const executeClassicScan = () => {
    console.log('🔍 hcitool scan 실행 중...');
    
    exec('timeout 20 sudo hcitool scan', { timeout: 25000 }, (error, stdout, stderr) => {
      if (error && error.killed) {
        console.log('⏱️ 타임아웃으로 종료됨 (정상)');
      }

      const lines = stdout.split('\n');
      lines
        .slice(1)
        .filter(line => line.trim() && !line.includes('Scanning'))
        .forEach(line => {
          const parts = line.trim().split(/\s+/);
          const mac = parts[0];
          const name = parts.slice(1).join(' ') || 'Unknown';
          
          // foundDevices 객체에 Classic 장치 추가 (BLE와 통합)
          foundDevices[mac] = {
            mac: mac,
            name: name,
            rssi: -50,
            type: 'Classic',
            lastSeen: Date.now()
          };
        });

      const classicCount = Object.values(foundDevices).filter(d => d.type === 'Classic').length;
      console.log(`📡 Classic 장치 ${classicCount}개 foundDevices에 추가됨`);
    });
  };

  // 첫 실행
  executeClassicScan();
  
  // 30초마다 반복 실행
  classicScanInterval = setInterval(executeClassicScan, 30000);
};

// =========================================================
// [3] 통합 전송 함수 (BLE + Classic)
// =========================================================

const sendAllDevicesToServer = () => {
  if (!socketClient) return;

  const deviceList = Object.values(foundDevices);
  
  if (deviceList.length > 0) {
    const bleCount = deviceList.filter(d => d.type === 'BLE').length;
    const classicCount = deviceList.filter(d => d.type === 'Classic').length;
    
    console.log(`📡 블루투스 장치 전송 중... (BLE: ${bleCount}, Classic: ${classicCount})`);
    
    socketClient.emit('bluetooth-scan', {
      deviceId: 'pi-001',
      devices: deviceList
    });

    // 오래된 기기(10초 이상 미감지) 삭제
    const now = Date.now();
    for (const mac in foundDevices) {
      if (now - foundDevices[mac].lastSeen > 10000) {
        delete foundDevices[mac];
      }
    }
  }
};

// =========================================================
// [4] 메인 초기화 함수
// =========================================================

const initUnifiedBluetoothScanner = (socket) => {
  socketClient = socket;
  console.log('🔵 통합 블루투스 스캐너 초기화 중...');

  // BLE 스캐너 초기화
  initBleScanner();

  // Classic 블루투스 스캐너 시작
  scanClassicBluetooth();

  // 5초마다 모든 장치를 서버로 전송
  if (scanInterval) clearInterval(scanInterval);
  scanInterval = setInterval(() => {
    sendAllDevicesToServer();
  }, 5000);
};

// =========================================================
// [5] 종료 및 정리 함수
// =========================================================

const stopUnifiedBluetoothScanner = () => {
  console.log('🛑 통합 블루투스 스캐너 종료 및 리소스 해제 중...');
  
  if (scanInterval) {
    clearInterval(scanInterval);
    scanInterval = null;
  }

  if (classicScanInterval) {
    clearInterval(classicScanInterval);
    classicScanInterval = null;
  }

  try {
    noble.stopScanning();
    console.log('✅ BLE 스캔 중지 완료');
  } catch (e) {
    console.error('⚠️ BLE 스캔 중지 중 오류:', e.message);
  }
  
  foundDevices = {};
  isScanning = false;
};

// =========================================================
// [6] 내보내기
// =========================================================

module.exports = { 
  initUnifiedBluetoothScanner, 
  stopUnifiedBluetoothScanner 
};