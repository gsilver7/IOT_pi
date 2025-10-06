// App.js
import useSocket from './hooks/useSocket';
import { useEffect, useState } from 'react';
import WebcamStreamClient from './components/WebcamStreamClient';
import WeatherDisplay from './components/WeatherDisplay';
import Grid from './components/Grid';
import WriteButton from './components/layout/WriteButton';
import styled from '@emotion/styled';
import { Global } from '@emotion/react';
import Sidebutton from './components/layout/Sidebutton';
import Contentbox from './components/layout/Contentbox';
import Tempbox from './components/layout/Tempbox';
import WindowFan from './components/layout/WindowFan';
import globalStyles from './styles/globalStyles';
import Light from './components/layout/Light';
import Visit from './components/layout/Visit';

const socketUrl = 'http://localhost:4000/';
interface SerialDataPayload {
  type : string;
  value: string;
}

const Sidediv = styled.div`
  height: 6%;
  user-select: none;
  padding-left:12%;
  padding-top:12%;
  font-weight: 700;
  font-size:130%;
`;

const Sidebar = styled.div`
  border:0;
  padding:0;
  color: white;
  border: none;
  height: 100%;
  width: 13%;
  float:left;
  position:fixed;
  background: #1A202E;

`;

const Titlebar = styled.div`
  height:7%;
  padding-left:3%;
  display: flex;
  align-items: center;
  font-size: 30px;
  background-color:#FFFFFF;
  box-shadow: 0px 4px 3px -2px #0000000F;
  position:fixed;
  left: 13%;
    width: 87%;
    z-index:10;
  `;


const Timebar = styled.div`
  margin-left: auto;
  margin-right:0;
  padding:0;
`;

function App() {
  const [homemode, setHomemode] = useState<string>('홈');

  const [message, setMessage] = useState(''); // 입력창의 내용을 관리할 state
  const socket = useSocket(socketUrl); // 이렇게 반환 값을 변수에 저장해야 합니다.
  const [serverTime, setServerTime] = useState('loadion');
  const [serialData, setSerialData] = useState<string | null>(null);
  const [temp, setTemp] = useState<string>('loading');

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

    const handleTemp = (payload: SerialDataPayload) => {
            console.log('온도 :', payload.value);
            setTemp(payload.value);
        }

    if (socket) { // socket이 성공적으로 연결되었을 때
      socket.on('connect', handleConnect);
      socket.on('disconnect', onDisconnect);
      socket.on('some-event', handleSomeEvent);
      socket.on('connect_error', handleError);
      socket.on('server-time', handleTime);
      socket.on('tempdata', handleTemp);
    }
  return () => {
    if (socket) {
      socket.off('connect', handleConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('some-event', handleSomeEvent);
      socket.off('connect_error', handleError);
      socket.off('server-time', handleTime);
      socket.off('tempdata', handleTemp);
    }
  }
  }, [socket]); // socket 객체가 변경될 때마다 useEffect 실행

  //'message'

  return (
      <body>
        <Global styles={globalStyles} />
        <Sidebar>
          <Sidediv>Smart Home</Sidediv>
          
          <Sidebutton onClick={() => {setHomemode('홈')}}
            imageSrc='/Home.svg'
            >홈</Sidebutton>
          <Sidebutton onClick={() => {setHomemode('조명')}}
            imageSrc='/Light.svg'>조명</Sidebutton>
          <Sidebutton onClick={() => {setHomemode('환기')}}
             imageSrc='/Wind.svg'>환기</Sidebutton>
          <Sidebutton onClick={() => {setHomemode('현관')}}
             imageSrc='/Video.svg'>현관</Sidebutton>
          <Sidebutton onClick={() => {setHomemode('방문객')}}
             imageSrc='/User.svg'>방문객</Sidebutton>
          <Sidebutton onClick={() => {setHomemode('기타')}}
             imageSrc='/User.svg'>기타</Sidebutton>
        </Sidebar>
        <Titlebar>{homemode}
          <Timebar>{serverTime}</Timebar>
        </Titlebar>
        
        <main>
          {homemode === '홈' && 
            <div><WeatherDisplay /><Grid/></div>
            
          }
          
          {homemode === '조명' && 
          <div>
          <Contentbox title="조명" description="집 안 조명 제어"/>
          <Light></Light>
          <WriteButton data="on" label="LED 켜기 (on)" />
          <WriteButton data="off" label="LED 끄기 (off)" />
          {serialData ? (
                  <p>Latest Data: {serialData}</p>
              ) : (
                  <p>Waiting for data...</p>
              )}
          </div>
          }

          {homemode === '현관' && 
          <div>
          <Contentbox title="현관" description="현관 CCTV 관찰"/>
          <WebcamStreamClient/>
          </div>
          }
          
          {homemode === '환기' && 
          <div>
          <Contentbox title="환기" description="온도, co2 농도에 따라 환기"/>
          <Tempbox temp={temp} co2='?'></Tempbox>
          <WindowFan></WindowFan>
          
          
          </div>
          }
        

          {homemode === '방문객' && 
          <div>
          <Contentbox title="방문객" description="현관 CCTV로 방문객 감지"/>
          <Visit></Visit>

          </div>
          }

          {homemode === '기타' && 
          <div>
            <input type="text" value={message}
          onChange={(e) => setMessage(e.target.value)}/>
          <button onClick={sendMessage} style={{ height: '50px', width: '200px' }}></button>          
          </div>
          }
          
        </main>
      </body>
  );
}

export default App;