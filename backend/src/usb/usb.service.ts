const usb = require('usb');

// 모든 USB 장치 목록 가져오기
const devices = usb.getDeviceList();

if (devices.length === 0) {
  console.log('USB 장치를 찾을 수 없습니다.');
} else {
  // 특정 장치 찾기 (예: Vendor ID와 Product ID 사용)
  const myDevice = usb.findByIds(0x1234, 0x5678); // 예시 ID
  
  if (myDevice) {
    console.log('USB 장치 발견:', myDevice.deviceDescriptor);
    
    // 장치 열기
    try {
      myDevice.open();
      
      // 장치와 통신하는 로직 (데이터 전송, 수신 등)
      // 이 부분은 장치의 종류에 따라 달라집니다.
      
      myDevice.close();
      console.log('장치가 성공적으로 닫혔습니다.');
    } catch (e) {
      console.error('장치를 열거나 통신하는 중 오류 발생:', e);
    }
    
  } else {
    console.log('지정된 USB 장치를 찾을 수 없습니다.');
  }
}