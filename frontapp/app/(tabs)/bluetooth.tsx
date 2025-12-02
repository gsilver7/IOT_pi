import { View, Button, Text, FlatList, StyleSheet, ScrollView, Alert } from 'react-native';
import RNBluetoothClassic, { BluetoothDevice } from 'react-native-bluetooth-classic';
import { useEffect, useState, useRef } from 'react';
import { PermissionsAndroid, Platform } from 'react-native';
import { io, Socket } from 'socket.io-client';

interface LogMessage {
  id: string;
  type: 'watch_to_app' | 'app_to_front' | 'front_to_app' | 'app_to_watch';
  data: string;
  timestamp: string;
}

export default function BluetoothScreen() {
  const [devices, setDevices] = useState<BluetoothDevice[]>([]);
  const [scanning, setScanning] = useState(false);
  const [connectedDevice, setConnectedDevice] = useState<BluetoothDevice | null>(null);
  const [socketConnected, setSocketConnected] = useState(false);
  const [logs, setLogs] = useState<LogMessage[]>([]);
  
  const socket = useRef<Socket | null>(null);

  const addLog = (type: LogMessage['type'], data: string) => {
    const newLog: LogMessage = {
      id: Date.now().toString(),
      type,
      data,
      timestamp: new Date().toLocaleTimeString()
    };
    setLogs(prev => [newLog, ...prev.slice(0, 49)]); // 최근 50개만 유지
  };

  useEffect(() => {
    initBluetooth();
    connectSocket();

    return () => {
      if (socket.current) {
        socket.current.disconnect();
      }
    };
  }, []);

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
      addLog('front_to_app', JSON.stringify(data));
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

  const handleSocketMessage = (data: any) => {
    if (connectedDevice) {
      const statusCommand = `S,${data?.mode},${data?.win},${data?.fan},${data?.hum},${data?.hit},${data?.glight},${data?.door},${data?.temp},${data?.humi},${data?.co2}\n`;
      addLog('app_to_watch', statusCommand);
      sendBluetoothCommand(statusCommand);
    }
  };

  const emitSocket = (event: string, data: any) => {
    if (socket.current?.connected) {
      socket.current.emit(event, data);
      console.log('Socket.IO 전송:', event, data);
      addLog('app_to_front', `${event}: ${JSON.stringify(data)}`);
    } else {
      Alert.alert('오류', 'Socket이 연결되지 않았습니다');
    }
  };

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

  const connectDevice = async (device: BluetoothDevice) => {
    try {
      if (connectedDevice) {
        await connectedDevice.disconnect();
      }

      const isConnected = await device.connect();
      
      if (isConnected) {
        setConnectedDevice(device);
        Alert.alert('성공', `${device.name}에 연결되었습니다`);
        
        device.onDataReceived((data: any) => {
          console.log('블루투스 수신:', data?.data);
          const receivedData = data?.data;
          addLog('watch_to_app', receivedData);
          
          if (receivedData?.startsWith('CMD,')) {
            const parts = receivedData.split(',');
            const key = parts[1];
            const value = parts[2]?.replace('\n', '');
            
            console.log('파싱:', key, value);
            
            emitSocket('bluetooth', {
              device: device.name,
              command: 'CMD',
              key: key,
              value: value
            });
          }
        });

        sendTimeSync(device);
      }
    } catch (error) {
      console.error('연결 실패:', error);
      Alert.alert('실패', '기기 연결 중 오류가 발생했습니다');
    }
  };

  const sendBluetoothCommand = async (data: string) => {
    if (!connectedDevice) {
      Alert.alert('오류', '연결된 기기가 없습니다');
      return;
    }
    
    try {
      console.log('📤 원본 데이터:', data);
      
      const base64Data = btoa(data);
      console.log('📤 Base64 인코딩:', base64Data);
      
      await connectedDevice.write(base64Data);
      
      console.log('✅ 블루투스 전송 완료');
    } catch (error) {
      // ✅ Error 타입으로 체크
      if (error instanceof Error) {
        console.error('❌ 전송 오류:', error.message);
        Alert.alert('전송 실패', error.message);
      } else {
        console.error('❌ 알 수 없는 오류:', error);
        Alert.alert('전송 실패', '알 수 없는 오류가 발생했습니다');
      }
    }
  };

  const sendTimeSync = async (device: BluetoothDevice) => {
    const now = new Date();
    const timeString = `T,${now.getFullYear()},${now.getMonth()+1},${now.getDate()},${now.getHours()},${now.getMinutes()},${now.getSeconds()}\n`;
    await device.write(timeString);
    console.log('시간 동기화:', timeString);
  };

  const disconnect = async () => {
    if (connectedDevice) {
      await connectedDevice.disconnect();
      setConnectedDevice(null);
      Alert.alert('알림', '연결 해제됨');
    }
  };

  const getLogColor = (type: LogMessage['type']) => {
    switch (type) {
      case 'watch_to_app': return '#2196F3'; // 파랑
      case 'app_to_front': return '#4CAF50'; // 초록
      case 'front_to_app': return '#FF9800'; // 주황
      case 'app_to_watch': return '#9C27B0'; // 보라
    }
  };

  const getLogLabel = (type: LogMessage['type']) => {
    switch (type) {
      case 'watch_to_app': return '워치→앱';
      case 'app_to_front': return '앱→프론트';
      case 'front_to_app': return '프론트→앱';
      case 'app_to_watch': return '앱→워치';
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

      {/* 통신 로그 */}
      <View style={styles.section}>
        <View style={styles.logHeader}>
          <Text style={styles.sectionTitle}>통신 로그</Text>
          <Button title="지우기" onPress={() => setLogs([])} color="#666" />
        </View>
        
        {logs.length === 0 ? (
          <Text style={styles.emptyText}>로그가 없습니다</Text>
        ) : (
          <FlatList
            data={logs}
            keyExtractor={(item) => item.id}
            scrollEnabled={false}
            renderItem={({ item }) => (
              <View style={styles.logItem}>
                <View style={styles.logHeader2}>
                  <View style={[styles.logBadge, { backgroundColor: getLogColor(item.type) }]}>
                    <Text style={styles.logBadgeText}>{getLogLabel(item.type)}</Text>
                  </View>
                  <Text style={styles.logTime}>{item.timestamp}</Text>
                </View>
                <Text style={styles.logData}>{item.data}</Text>
              </View>
            )}
          />
        )}
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
  emptyText: {
    fontSize: 14,
    color: '#999',
    textAlign: 'center',
    padding: 16,
  },
  logHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  logItem: {
    backgroundColor: '#fafafa',
    padding: 12,
    borderRadius: 8,
    marginBottom: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#ddd',
  },
  logHeader2: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 6,
  },
  logBadge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  logBadgeText: {
    color: 'white',
    fontSize: 12,
    fontWeight: '600',
  },
  logTime: {
    fontSize: 11,
    color: '#666',
  },
  logData: {
    fontSize: 13,
    fontFamily: 'monospace',
    color: '#333',
  },
});