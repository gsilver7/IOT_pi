// useSocket.tsx 파일
import { useEffect, useState } from "react";
import { io, Socket } from "socket.io-client";

const SOCKET_URL = "https://kmj.shscript.com";

// ✅ 싱글톤 패턴: 전역에서 하나의 소켓만 유지
let socketInstance: Socket | null = null;

const useSocket = () => {
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    // 이미 연결된 소켓이 있으면 재사용
    if (socketInstance?.connected) {
      console.log("♻️ 기존 소켓 재사용:", socketInstance.id);
      setSocket(socketInstance);
      return;
    }

    // 소켓이 없거나 연결이 끊어진 경우 새로 생성
    if (!socketInstance) {
      console.log("🔌 새 소켓 생성 중...");
      socketInstance = io(SOCKET_URL, {
        transports: ["websocket", "polling"], // polling -> websocket 순서로 시도
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 10,
        timeout: 20000,
      });

      socketInstance.on("connect", () => {
        console.log("✅ Socket 연결 성공! ID:", socketInstance?.id);
      });

      socketInstance.on("connect_error", (error) => {
        console.error("❌ Socket 연결 실패:", error.message);
      });

      socketInstance.on("disconnect", (reason) => {
        console.warn("⚠️ Socket 연결 끊김:", reason);
      });
    }

    setSocket(socketInstance);

    // ✅ cleanup: 컴포넌트 언마운트 시에도 소켓 유지
    return () => {
      console.log("🧹 useSocket cleanup (연결 유지)");
      // disconnect 하지 않음 - 다른 컴포넌트에서 재사용
    };
  }, []);

  return socket;
};

export default useSocket;