import { View, Button, Text, FlatList, StyleSheet, ScrollView, Alert } from 'react-native';
import RNBluetoothClassic, { BluetoothDevice } from 'react-native-bluetooth-classic';
import { useEffect, useState, useRef } from 'react';
import { PermissionsAndroid, Platform } from 'react-native';
import { io, Socket } from 'socket.io-client';

export default function BluetoothScreen() {
  const [devices, setDevices] = useState<BluetoothDevice[]>([]);
  const [scanning, setScanning] = useState(false);
  const [connectedDevice, setConnectedDevice] = useState<BluetoothDevice | null>(null);
  const [socketConnected, setSocketConnected] = useState(false);
  
  const socket = useRef<Socket | null>(null);

  useEffect(() => {
    initBluetooth();
    connectSocket();

    return () => {
      if (socket.current) {
        socket.current.disconnect();
      }
    };
  }, []);

  // 블루투스 초기화
  const initBluetooth = async () => {
    if (Platform.OS === 'android') {
      await PermissionsAndroid.requestMultiple([
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
      ]);
    }

    const enabled = await RNBluetoothClassic.isBluetoothEnabled();
    if (!enabled) {
      await RNBluetoothClassic.requestBluetoothEnabled();
    }
  };

  // Socket.IO 연결
  const connectSocket = () => {
    socket.current = io('https://kmj.shscript.com', {
      transports: ['websocket'],
      reconnection: true,
      reconnectionDelay: 5000,
    });

    socket.current.on('connect', () => {
      console.log('Socket.IO 연결됨');
      setSocketConnected(true);
      socket.current?.emit('init', { clientId: 'mobile-app' });
    });

    socket.current.on('sensor-data', (data) => {
      console.log('Socket.IO 수신:', data);
      handleSocketMessage(data);
    });

    socket.current.on('disconnect', () => {
      console.log('Socket.IO 연결 종료');
      setSocketConnected(false);
    });

    socket.current.on('error', (error) => {
      console.error('Socket.IO 오류:', error);
    });
  };

  // Socket 메시지 처리
  const handleSocketMessage = (data: any) => {
    if (connectedDevice) {

      const statusCommand = `S,${data?.mode},${data?.win},${data?.fan},${data?.hum},${data?.hit},${data?.glight},${data?.door},${data?.temp},${data?.humi},${data?.co2}\n`;
  
      sendBluetoothCommand(statusCommand);
    }
  };

  // Socket 메시지 전송
  const emitSocket = (event: string, data: any) => {
    if (socket.current?.connected) {
      socket.current.emit(event, data);
      console.log('Socket.IO 전송:', event, data);
    } else {
      Alert.alert('오류', 'Socket이 연결되지 않았습니다');
    }
  };

  // 블루투스 스캔
  const scanDevices = async () => {
    setScanning(true);
    try {
      const paired = await RNBluetoothClassic.getBondedDevices();
      const unpaired = await RNBluetoothClassic.startDiscovery();
      setDevices([...paired, ...unpaired]);
    } catch (error) {
      console.error('스캔 오류:', error);
      Alert.alert('오류', '블루투스 스캔 실패');
    } finally {
      setScanning(false);
    }
  };

  // 블루투스 연결
  const connectDevice = async (device: BluetoothDevice) => {
    try {
      if (connectedDevice) {
        await connectedDevice.disconnect();
      }

      const isConnected = await device.connect();
      
      if (isConnected) {
        setConnectedDevice(device);
        Alert.alert('성공', `${device.name}에 연결되었습니다`);
        
        // 데이터 수신 리스너 - 블루투스에서 받은 데이터를 Socket으로 전송
        device.onDataReceived((data: any) => {
          console.log('블루투스 수신:', data?.data);
          
          const receivedData = data?.data;
          
          // CMD로 시작하는 명령 파싱
          if (receivedData?.startsWith('CMD,')) {
            const parts = receivedData.split(',');
            const key = parts[1]; // LIGHT, MODE 등
            const value = parts[2]?.replace('\n', ''); // 1, 2 등
            
            console.log('파싱:', key, value);
            
            // Socket으로 전송
            emitSocket('bluetooth', {
              device: device.name,
              command: 'CMD',
              key: key,
              value: value
            });
          }
        });

        // 시간 동기화
        sendTimeSync(device);
        
      }
    } catch (error) {
      console.error('연결 실패:', error);
      Alert.alert('실패', '기기 연결 중 오류가 발생했습니다');
    }
  };

  // 블루투스 명령 전송
  const sendBluetoothCommand = async (data: any) => {
    if (!connectedDevice) {
      Alert.alert('오류', '연결된 기기가 없습니다');
      return;
    }
    
    try {
      await connectedDevice.write(data);
      console.log('블루투스 전송:', data);
    } catch (error) {
      console.error('전송 오류:', error);
    }
  };

  // 시간 동기화
  const sendTimeSync = async (device: BluetoothDevice) => {
    const now = new Date();
    const timeString = `T,${now.getFullYear()},${now.getMonth()+1},${now.getDate()},${now.getHours()},${now.getMinutes()},${now.getSeconds()}\n`;
    await device.write(timeString);
    console.log('시간 동기화:', timeString);
  };

  // 연결 해제
  const disconnect = async () => {
    if (connectedDevice) {
      await connectedDevice.disconnect();
      setConnectedDevice(null);
      Alert.alert('알림', '연결 해제됨');
    }
  };


  return (
    <ScrollView style={styles.container}>
      {/* 연결 상태 */}
      <View style={styles.section}>
        <View style={styles.statusRow}>
          <View style={styles.statusItem}>
            <View style={[styles.statusDot, { backgroundColor: socketConnected ? '#4caf50' : '#f44336' }]} />
            <Text>Socket.IO</Text>
          </View>
          <View style={styles.statusItem}>
            <View style={[styles.statusDot, { backgroundColor: connectedDevice ? '#4caf50' : '#f44336' }]} />
            <Text>Bluetooth</Text>
          </View>
        </View>
      </View>

      {/* 블루투스 스캔 */}
      <View style={styles.section}>
        <Button 
          title={scanning ? "스캔 중..." : "블루투스 스캔"} 
          onPress={scanDevices}
          disabled={scanning}
        />
        
        {connectedDevice && (
          <View style={styles.connectedInfo}>
            <Text style={styles.connectedText}>
              연결됨: {connectedDevice.name}
            </Text>
            <Button title="연결 해제" onPress={disconnect} color="#ff4444" />
          </View>
        )}
      </View>

      {/* 기기 목록 */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>검색된 기기</Text>
        <FlatList
          data={devices}
          keyExtractor={(item) => item.address}
          scrollEnabled={false}
          renderItem={({ item }) => (
            <View style={styles.deviceItem}>
              <View style={styles.deviceInfo}>
                <Text style={styles.deviceName}>
                  {item.name || '이름 없음'}
                </Text>
                <Text style={styles.deviceAddress}>{item.address}</Text>
              </View>
              <Button 
                title={connectedDevice?.address === item.address ? "연결됨" : "연결"} 
                onPress={() => connectDevice(item)}
                disabled={connectedDevice?.address === item.address}
              />
            </View>
          )}
        />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  section: {
    padding: 16,
    backgroundColor: 'white',
    marginVertical: 8,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 12,
  },
  statusRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingVertical: 8,
  },
  statusItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  statusDot: {
    width: 12,
    height: 12,
    borderRadius: 6,
  },
  connectedInfo: {
    marginTop: 12,
    padding: 12,
    backgroundColor: '#e8f5e9',
    borderRadius: 8,
  },
  connectedText: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 8,
  },
  deviceItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 12,
    backgroundColor: '#fafafa',
    borderRadius: 8,
    marginBottom: 8,
  },
  deviceInfo: {
    flex: 1,
  },
  deviceName: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 4,
  },
  deviceAddress: {
    fontSize: 12,
    color: '#666',
  },
  commandButtons: {
    gap: 8,
  },
  buttonSpacer: {
    height: 8,
  },
  messageText: {
    fontSize: 12,
    fontFamily: 'monospace',
    padding: 8,
    backgroundColor: '#f5f5f5',
    borderRadius: 4,
    marginBottom: 4,
  },
  emptyText: {
    fontSize: 14,
    color: '#999',
    textAlign: 'center',
    padding: 16,
  },
});