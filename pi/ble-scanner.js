// ble-scanner.js
const noble = require('@abandonware/noble');

let socketClient = null;
let foundDevices = {}; // 중복 제거 및 최신 RSSI 유지를 위한 객체
let isScanning = false;
let scanInterval = null;

// =========================================================
// [1] 기능 함수들 (먼저 정의해야 에러가 안 남)
// =========================================================

// 1-1. 스캔 시작 함수
const startScan = async () => {
  if (isScanning) return;
  try {
    // [], true -> 모든 서비스 UUID 스캔, 중복 허용(RSSI 업데이트 위해)
    await noble.startScanningAsync([], true); 
    isScanning = true;
    console.log('✅ 블루투스 스캔 시작됨');
  } catch (e) {
    console.error('🔴 스캔 시작 실패:', e);
  }
};

// 1-2. 서버 전송 함수
const sendDevicesToServer = () => {
  if (!socketClient) return;

  const deviceList = Object.values(foundDevices);
  
  // 감지된 기기가 있을 때만 전송
  if (deviceList.length > 0) {
    console.log(`📡 블루투스 장치 ${deviceList.length}개 전송 중...`);
    
    socketClient.emit('bluetooth-scan', {
      deviceId: 'pi-001',
      devices: deviceList
    });

    // 오래된 기기(10초 이상 미감지) 삭제 로직
    const now = Date.now();
    for (const mac in foundDevices) {
      if (now - foundDevices[mac].lastSeen > 10000) {
        delete foundDevices[mac];
      }
    }
  }
};

// =========================================================
// [2] 메인 초기화 함수 (이제 startScan을 알 수 있음)
// =========================================================
const initBleScanner = (socket) => {
  socketClient = socket;

  console.log('🔵 BLE 스캐너 초기화 중...');

  // 블루투스 상태 변경 감지
  noble.on('stateChange', async (state) => {
    if (state === 'poweredOn') {
      console.log('🔵 블루투스 어댑터 켜짐 (poweredOn)');
      // 여기서 startScan을 부를 때, 위에서 이미 정의했으므로 에러 안 남
      startScan();
    } else {
      console.log('🔴 블루투스 꺼짐 (State:', state, ')');
      noble.stopScanning();
      isScanning = false;
    }
  });

  // 장치 발견 시 실행될 함수
  noble.on('discover', (peripheral) => {
    const mac = peripheral.address;
    
    // 객체에 저장 (이미 있으면 RSSI 갱신)
    foundDevices[mac] = {
      mac: mac,
      name: peripheral.advertisement.localName || 'Unknown',
      rssi: peripheral.rssi, // 신호 강도
      lastSeen: Date.now()
    };
  });

  // 5초마다 서버로 전송
  if (scanInterval) clearInterval(scanInterval);
  scanInterval = setInterval(() => {
    sendDevicesToServer();
  }, 5000);
};

// =========================================================
// [3] 종료 및 정리 함수
// =========================================================
const stopBleScanner = () => {
  console.log('🛑 BLE 스캐너 종료 및 리소스 해제 중...');
  
  if (scanInterval) {
    clearInterval(scanInterval);
    scanInterval = null;
  }

  try {
    noble.stopScanning();
    console.log('✅ 블루투스 스캔 중지 완료');
  } catch (e) {
    console.error('⚠️ 스캔 중지 중 오류:', e.message);
  }
};

// 내보내기
module.exports = { initBleScanner, stopBleScanner };