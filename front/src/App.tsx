// App.js
import useSocket from "./hooks/useSocket";
import { useEffect, useState, useContext } from "react";
import { OnoffContext } from "./context/OnoffContext";
import Contentbox from "./components/layout/Contentbox";
import Tempbox from "./components/layout/Tempbox";

interface AduDataDto {
  temp: string;
  humi: string;
  co2: string;
  light: string;
  timestamp: string;
  deviceId: string;
}

function App() {
  interface ControlMessage {
    light: boolean;
    w: boolean;
    fan: boolean;
  }

  const socket = useSocket(); // 이렇게 반환 값을 변수에 저장해야 합니다.
  const { hlight, win, fan, setServerTime } = useContext(OnoffContext);

  const [temp, setTemp] = useState<string>("loading");
  const [humi, setHumi] = useState<string>("loading");
  const [co2, setCo2] = useState<string>("loading");
  const [light, setLight] = useState<string>("loading");

  useEffect(() => {
    const controlMessage: ControlMessage = {
      light: hlight,
      w: win,
      fan: fan,
    };

    console.log("제어 상태 변경:", controlMessage);

    if (socket) {
      socket.emit("control", controlMessage);
    }
  }, [hlight, win, fan, socket]); // 모든 의존성 포함

  // 이제 'socket' 변수를 사용해서 통신할 수 있습니다.
  useEffect(() => {
    const onDisconnect = (reason: string) => {
      console.log(`❌ 서버와 연결이 끊어졌습니다. 원인: ${reason}`);
    };
    const handleConnect = () => {
      // ✅ socket 객체가 존재하는지 먼저 확인합니다.
      if (socket) {
        console.log("소켓 연결 성공! ID:", socket.id);
      } else {
        // 소켓이 아직 연결되지 않았을 때의 로직
        console.log("소켓이 아직 연결되지 않았습니다.");
      }
    };

    const handleError = (err: unknown) => {
      // ✅ Check if 'err' is an instance of the 'Error' class
      if (err instanceof Error) {
        console.error(`연결 시도 실패: ${err.message}`);
      } else {
        // Handle cases where 'err' is not an Error object (e.g., a string or number)
        console.error("알 수 없는 오류가 발생했습니다.");
      }
    };

    const handleTime = (data: { timestamp: string }) => {
      console.log("서버시간 수신:", data);
      const formattedTime = new Date(data.timestamp).toLocaleString("ko-KR");
      setServerTime(formattedTime);
    };

    const handleSomeEvent = (data: string) => {
      console.log("서버로부터 받은 데이터:", data);
    };

    const handleData = (payload: AduDataDto) => {
      setTemp(payload.temp);
      setHumi(payload.humi);
      setCo2(payload.co2);
      setLight(payload.light);
    };

    if (socket) {
      // socket이 성공적으로 연결되었을 때
      socket.on("connect", handleConnect);
      socket.on("disconnect", onDisconnect);
      socket.on("some-event", handleSomeEvent);
      socket.on("connect_error", handleError);
      socket.on("server-time", handleTime);
      socket.on("adu-data", handleData);
    }
    return () => {
      if (socket) {
        socket.off("connect", handleConnect);
        socket.off("disconnect", onDisconnect);
        socket.off("some-event", handleSomeEvent);
        socket.off("connect_error", handleError);
        socket.off("server-time", handleTime);
        socket.off("adu-data", handleData);
      }
    };
  }, [socket]); // socket 객체가 변경될 때마다 useEffect 실행

  return (
    <div>
      <Contentbox title="센서" description="집 안 센서 정보" />

      <Tempbox temp={temp} humi={humi} co2={co2} light={light}></Tempbox>
    </div>
  );
}

export default App;
