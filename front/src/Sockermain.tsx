// hooks/useSmartHomeSocket.ts
import { useEffect, useContext } from "react";
import useSocket from "./hooks/useSocket";
import { OnoffContext } from "./context/OnoffContext";
import { useGlobalState } from "./context/GlobalStateContext";

// DTO 타입 정의
export interface AduDataDto {
  temp: string;
  humi: string;
  co2: string;
  light: string;
}
export interface MacMatchDto {
  matched: boolean;
  macs: string[];
  devices: Array<{
    mac: string;
    rssi: number;
    name: string;
  }>;
  users: Array<{
    id: number;
    name: string;
  }>;
  timestamp: string;
}

interface ControlMessage {
  light: number;
  w: number;
  fan: number;
  mode: string;
}

export const Socketmain = () => {

  const { modetype, triggerStateB } = useGlobalState();

  const socket = useSocket();
  const {
    hlight,
    win,
    fan,
    setServerTime,
    setTemp,
    setHumi,
    setCo2,
    setLight
  } = useContext(OnoffContext);

  // 센서 데이터 상태 관리

  // 1. 제어 상태(Context)가 바뀌면 소켓으로 전송 (Emit)
  useEffect(() => {
    const controlMessage: ControlMessage = {
      light: hlight,
      w: win,
      fan: fan,
      mode:modetype
    };

    if (socket) {
      console.log("📤 제어 상태 전송:", controlMessage);
      socket.emit("control", controlMessage);
    }
  }, [hlight, win, fan, modetype, socket]);

  // 2. 소켓 이벤트 리스너 등록 (Receive)
  useEffect(() => {
    if (!socket) return;

    // 핸들러 함수들
    const handleConnect = () =>
      console.log("✅ 소켓 연결 성공! ID:", socket.id);
    const onDisconnect = (reason: string) =>
      console.log(`❌ 연결 끊김: ${reason}`);
    const handleError = (err: unknown) => console.error("소켓 에러:", err);

    const handleTime = (data: { timestamp: string }) => {
      console.log("⏰ 서버시간 수신:", data);
      setServerTime(data.timestamp);
    };

    const handleData = (payload: AduDataDto) => {
      setTemp(payload.temp);

      setHumi(payload.humi);

      setCo2(payload.co2);

      setLight(payload.light);
    };

    const handlemacData = (data:MacMatchDto) => {
    console.log('✅ 등록된 블루투스 장치 감지!', data);
    
    const userNames = (data.users ?? []).map(u => u.name).join(', ');    
    const macAddresses = data.macs.join(', ');
    
    console.log(`등록된 사용자의 블루투스 장치가 감지되었습니다!\n사용자: ${userNames}\nMAC: ${macAddresses}`);

    triggerStateB();
    
  }
    // 이벤트 등록
    socket.on("connect", handleConnect);
    socket.on("disconnect", onDisconnect);
    socket.on("connect_error", handleError);
    socket.on("server-time", handleTime);
    socket.on("adu-data", handleData);
    socket.on("mac", handlemacData);

    // 클린업 (언마운트 시 리스너 제거)
    return () => {
      socket.off("connect", handleConnect);
      socket.off("disconnect", onDisconnect);
      socket.off("connect_error", handleError);
      socket.off("server-time", handleTime);
      socket.off("adu-data", handleData);
      socket.off("mac", handlemacData);
    };
  }, [socket]);

  // UI에서 필요한 데이터만 반환
  return null;
};
