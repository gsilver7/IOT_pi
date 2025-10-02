// App.js
import useSocket from './hooks/useSocket';
import { useEffect, useState } from 'react';
import WebcamStreamClient from './components/WebcamStreamClient';

const socketUrl = 'http://192.168.186.179:4000/';


function App() {
  const [message, setMessage] = useState(''); // 입력창의 내용을 관리할 state
  const socket = useSocket(socketUrl); // 이렇게 반환 값을 변수에 저장해야 합니다.
  const [serverTime, setServerTime] = useState('서버 시간 대기 중...');

  const sendMessage = () => {
    // 소켓이 연결되어 있고, 메시지가 비어있지 않을 때만 전송
    if (socket && message.trim()) {
      // 백엔드의 @SubscribeMessage('message')를 호출합니다.
      socket.emit('message', message);
      setMessage(''); // 메시지 전송 후 입력창 비우기
    }
  };
  // 이제 'socket' 변수를 사용해서 통신할 수 있습니다.
  useEffect(() => {
    const onDisconnect = (reason: string) => {
      console.log(`❌ 서버와 연결이 끊어졌습니다. 원인: ${reason}`);
    };
    const handleConnect = () => {
      // ✅ socket 객체가 존재하는지 먼저 확인합니다.
      if (socket) {
        console.log('소켓 연결 성공! ID:', socket.id);
      } else {
        // 소켓이 아직 연결되지 않았을 때의 로직
        console.log('소켓이 아직 연결되지 않았습니다.');
      }
    };

    const handleError = (err: unknown) => {
      // ✅ Check if 'err' is an instance of the 'Error' class
      if (err instanceof Error) {
        console.error(`연결 시도 실패: ${err.message}`);
      } else {
        // Handle cases where 'err' is not an Error object (e.g., a string or number)
        console.error('알 수 없는 오류가 발생했습니다.');
      }
    };

    const handleTime = (data:{ timestamp: string }) => {
      console.log('서버시간 수신:', data);
      const formattedTime = new Date(data.timestamp).toLocaleString('ko-KR');
      setServerTime(formattedTime);
    };
    
    const handleSomeEvent = (data: string) => {
      console.log('서버로부터 받은 데이터:', data);
      
    };

    if (socket) { // socket이 성공적으로 연결되었을 때
      socket.on('connect', handleConnect);
      socket.on('disconnect', onDisconnect);
      socket.on('some-event', handleSomeEvent);
      socket.on('connect_error', handleError);
      socket.on('server-time', handleTime);

    }
  return () => {
    if (socket) {
      socket.off('connect', handleConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('some-event', handleSomeEvent);
      socket.off('connect_error', handleError);
      socket.off('server-time', handleTime);
    }
  }
  }, [socket]); // socket 객체가 변경될 때마다 useEffect 실행

  //'message'

  return (

      <div>
        <></>
         <WebcamStreamClient/>
        <h1>front end</h1>
        <h2>서버 시간: {serverTime}</h2>
        <input 
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}/>
        <button onClick={sendMessage} style={{ height: '50px', width: '200px' }}></button>
      </div>

  );
}

export default App;