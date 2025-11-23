import { View, Button, Text, FlatList } from 'react-native';
import RNBluetoothClassic, { BluetoothDevice } from 'react-native-bluetooth-classic';
import { useEffect, useState } from 'react';
import { PermissionsAndroid, Platform, Alert } from 'react-native';
import WebViewComponent from '../../components/webview';

export default function TabOneScreen() {
  const [devices, setDevices] = useState<BluetoothDevice[]>([]);
  const [scanning, setScanning] = useState<boolean>(false);
  const [connectedDevice, setConnectedDevice] = useState<BluetoothDevice | null>(null);

  useEffect(() => {
    requestPermissions();
    checkBluetoothEnabled();
  }, []);

  const requestPermissions = async () => {
    if (Platform.OS === 'android') {
      const granted = await PermissionsAndroid.requestMultiple([
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
      ]);
      console.log('권한 상태:', granted);
    }
  };

  const checkBluetoothEnabled = async () => {
    try {
      const enabled = await RNBluetoothClassic.isBluetoothEnabled();
      if (!enabled) {
        Alert.alert('블루투스', '블루투스를 켜주세요');
        await RNBluetoothClassic.requestBluetoothEnabled();
      }
    } catch (error) {
      console.error('블루투스 확인 오류:', error);
    }
  };

  const scanDevices = async () => {
    try {
      setScanning(true);
      
      const paired = await RNBluetoothClassic.getBondedDevices();
      console.log('페어링된 기기:', paired);
      
      const unpaired = await RNBluetoothClassic.startDiscovery();
      console.log('검색된 기기:', unpaired);
      
      const allDevices = [...paired, ...unpaired];
      setDevices(allDevices);
      
      setScanning(false);
    } catch (error) {
      console.error('스캔 오류:', error);
      setScanning(false);
      Alert.alert('오류', '블루투스 스캔 실패');
    }
  };

  const connectDevice = async (device: BluetoothDevice) => {
    try {
      if (connectedDevice) {
        await connectedDevice.disconnect();
      }

      console.log('연결 시도:', device.name, device.address);
      
      // [수정 1] 반환값은 연결 여부(boolean)입니다. 변수명을 isConnected로 바꾸면 이해하기 쉽습니다.
      const isConnected = await device.connect();
      
      // [수정 2] 연결에 성공했을 때만 로직을 수행합니다.
      if (isConnected) {
        // [수정 3] 상태에는 true/false가 아니라 'device' 객체 자체를 넣어야 합니다.
        setConnectedDevice(device);
        
        Alert.alert('성공', `${device.name}에 연결되었습니다`);
        
        // [수정 4] onDataReceived는 'connection'(boolean)이 아니라 'device'(객체)에 써야 합니다.
        device.onDataReceived((data: any) => {
          console.log('수신 데이터:', data?.data);
        });

        // [수정 5] 여기서도 connection 대신 device를 넘겨줍니다.
        sendTimeSync(device);
      } else {
        Alert.alert('실패', '기기 연결에 실패했습니다 (반환값 false)');
      }
      
    } catch (error) {
      console.error('연결 실패:', error);
      Alert.alert('실패', '기기 연결 중 오류가 발생했습니다');
    }
  };

  const sendTimeSync = async (device: BluetoothDevice) => {
    try {
      const now = new Date();
      const timeString = `T,${now.getFullYear()},${now.getMonth()+1},${now.getDate()},${now.getHours()},${now.getMinutes()},${now.getSeconds()}\n`;
      
      await device.write(timeString);
      console.log('시간 동기화 전송:', timeString);
    } catch (error) {
      console.error('전송 오류:', error);
    }
  };

  const sendCommand = async (command: string) => {
    if (!connectedDevice) {
      Alert.alert('오류', '연결된 기기가 없습니다');
      return;
    }
    
    try {
      await connectedDevice.write(command + '\n');
      console.log('명령 전송:', command);
    } catch (error) {
      console.error('전송 오류:', error);
    }
  };

  const disconnect = async () => {
    if (connectedDevice) {
      try {
        await connectedDevice.disconnect();
        setConnectedDevice(null);
        Alert.alert('알림', '연결 해제됨');
      } catch (error) {
        console.error('연결 해제 오류:', error);
      }
    }
  };

  return (
    <View>
      <View style={{ zIndex: 100, position: 'absolute' }}>
        <Button 
          title={scanning ? "스캔 중..." : "블루투스 스캔"} 
          onPress={scanDevices}
          disabled={scanning}
        />
        
        {connectedDevice && (
          <View>
            <Text>연결됨: {connectedDevice.name}</Text>
            <Button title="연결 해제" onPress={disconnect} />
          </View>
        )}

        <FlatList
          data={devices}
          keyExtractor={(item) => item.address}
          renderItem={({ item }) => (
            <View>
              <Text>{item.name || '이름 없음'}</Text>
              <Text>{item.address}</Text>
              <Button 
                title={connectedDevice?.address === item.address ? "연결됨" : "연결"} 
                onPress={() => connectDevice(item)}
                disabled={connectedDevice?.address === item.address}
              />
            </View>
          )}
        />

        {connectedDevice && (
          <View>
            <Button title="현관등 켜기" onPress={() => sendCommand('CMD,L1,1')} />
            <Button title="현관등 끄기" onPress={() => sendCommand('CMD,L1,0')} />
            <Button title="시간 동기화" onPress={() => sendTimeSync(connectedDevice)} />
          </View>
        )}
      </View>

      <WebViewComponent initialUrl="http://192.168.197.179:3000/" showControls={true} />    
    </View>
  );
}