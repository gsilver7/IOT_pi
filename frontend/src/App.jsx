// App.js
import { RecoilRoot } from 'recoil';
import SocketManager from './SocketManager';
import useSocket from './hooks/useSocket';
import { useEffect, useState } from 'react';

const socketUrl = 'http://192.168.137.154:4000/';


function App() {
  const [message, setMessage] = useState(''); // 입력창의 내용을 관리할 state
  const socket = useSocket(socketUrl); // 이렇게 반환 값을 변수에 저장해야 합니다.

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
    const onDisconnect = (reason) => {
      console.log(`❌ 서버와 연결이 끊어졌습니다. 원인: ${reason}`);
    };
    const handleConnect = () => {
      console.log('소켓 연결 성공! ID:', socket.id);
    };
    const handleError = (err) => {
      console.error(`연결 시도 실패: ${err.message}`);
    };
    const handleSomeEvent = (data) => {
      console.log('서버로부터 받은 데이터:', data);
    };

    if (socket) { // socket이 성공적으로 연결되었을 때
      socket.on('connect', handleConnect);
      socket.on('disconnect', onDisconnect);
      socket.on('some-event', handleSomeEvent);
      socket.on('connect_error', handleError);

    }
  return () => {
    if (socket) {
      socket.off('connect', handleConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('some-event', handleSomeEvent);
      socket.off('connect_error', handleError);
    }
  }
  }, [socket]); // socket 객체가 변경될 때마다 useEffect 실행

  //'message'

  return (
    <RecoilRoot>
      <div>
        <h1>front end</h1>
        <input 
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}/>
        <button onClick={sendMessage} style={{ height: '50px', width: '200px' }}></button>
      </div>
    </RecoilRoot>
  );
}

export default App;