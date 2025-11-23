import { View, Button, Text, FlatList, StyleSheet } from 'react-native';
import { BleManager,Device  } from 'react-native-ble-plx';
import { useEffect, useState } from 'react';
import { PermissionsAndroid, Platform } from 'react-native';
import WebViewComponent from '../../components/webview';

const manager = new BleManager();

export default function TabOneScreen() {
    const [devices, setDevices] = useState<Device[]>([]);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    requestPermissions();
    
    return () => {
      manager.destroy();
    };
  }, []);

  const requestPermissions = async () => {
    if (Platform.OS === 'android') {
      await PermissionsAndroid.requestMultiple([
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
      ]);
    }
  };

  const scanDevices = () => {
    setScanning(true);
    setDevices([]);
    
    manager.startDeviceScan(null, null, (error, device) => {
      if (error) {
        console.error(error);
        return;
      }
      
      if (device && device.name) {
        console.log('발견된 기기:', device.name, device.id);
        setDevices(prev => {
          if (!prev.find(d => d.id === device.id)) {
            return [...prev, device];
          }
          return prev;
        });
      }
    });

    setTimeout(() => {
      manager.stopDeviceScan();
      setScanning(false);
    }, 10000);
  };

  const connectDevice = async (deviceId : string) => {
    try {
      const device = await manager.connectToDevice(deviceId);
      await device.discoverAllServicesAndCharacteristics();
      console.log('연결 성공:', device.name);
      alert(`${device.name}에 연결되었습니다`);
    } catch (error) {
      console.error('연결 실패:', error);
      alert('연결 실패');
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
            <FlatList
              data={devices}
              keyExtractor={(item) => item.id}
              renderItem={({ item }) => (
                <View>
                  <Text>{item.name || '이름 없음'}</Text>
                  <Button 
                    title="연결" 
                    onPress={() => connectDevice(item.id)}
                  />
                </View>
              )}
            />
        </View>
      <WebViewComponent initialUrl="http://192.168.197.179:3000/" showControls={true} />    
    </View>
    
  );
}