// App.js
import useSocket from "./hooks/useSocket";
import { useEffect, useState, useContext } from "react";
import { OnoffContext } from "./context/OnoffContext";
import WebcamStreamClient from "./components/WebcamStreamClient";
import WeatherDisplay from "./components/WeatherDisplay";
import Grid from "./components/Grid";
import styled from "@emotion/styled";
import { Global } from "@emotion/react";
import Sidebutton from "./components/layout/Sidebutton";
import Contentbox from "./components/layout/Contentbox";
import Tempbox from "./components/layout/Tempbox";
import globalStyles from "./styles/globalStyles";
import Controlbox from "./components/layout/Controlbox";
import Visit from "./components/layout/Visit";
import ModeButton from "./components/layout/Modebutton";

interface AduDataDto {
  temp: string;
  humi: string;
  co2: string;
  light: string;
  timestamp: string;
  deviceId: string;
}

const Sidediv = styled.div`
  height: 6%;
  user-select: none;
  padding-left: 12%;
  padding-top: 12%;
  font-weight: 700;
  font-size: 130%;
`;

const Sidebar = styled.div`
  border: 0;
  padding: 0;
  color: white;
  border: none;
  height: 100%;
  width: 13%;
  float: left;
  background: #1a202e;
  @media (max-width: 800px) {
    display: none;
  }
  z-index: 10;
`;

const Mobabar = styled.div<{ $toggle: boolean }>`
  border: 0;
  padding: 0;
  color: white;
  border: none;
  height: 100%;
  width: 13%;
  float: left;
  background: #1a202e;
  @media (min-width: 800px) {
    display: none;
  }
  position: absolute;
  top: 0;
  left: 0;
  width: 30%;
  z-index: 20;
  left: ${(props) => (props.$toggle ? "0" : "-300px")};
  transition: left 0.6s ease-in-out;
`;

const Titlebar = styled.div`
  height: 7%;
  padding-left: 3%;
  display: flex;
  align-items: center;
  font-size: 30px;
  background-color: #ffffff;
  box-shadow: 0px 4px 3px -2px #0000000f;
  z-index: 10;
  top: 0;
  position: fixed;
  width: 100%;
`;
const Sdiv = styled.div`
  margin: 3%;
  background-color: white;
  padding: 3%;
`;

const Timebar = styled.div`
  margin-left: auto;
  margin-right: 0;
  padding: 0;
  padding-right: 5%;
  @media (max-width: 800px) {
    font-size: 20px;
  }
`;

const Body = styled.body`
  display: flex;
  flex-direction: row;
`;

const Main = styled.main`
  display: flex;
  height: 100vh;
  flex-direction: column;
  margin: 0;
  paddint: 0;
`;
const HomeModeText = styled.span`
  @media (max-width: 800px) {
    display: none;
  }
`;

const Mobamenu = styled.button`
  @media (min-width: 800px) {
    display: none;
  }
  background: transparent;
  border: none;
  padding: 0;
  cursor: pointer;
`;

const Over = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  backgroundcolor: rgba(0, 0, 0, 0.5); // 반투명 배경
  z-index: 10;
`;

const Div = styled.div`
  position: relative;
  top: 7%;
  padding-top: 3%;
`;

const Modebox = styled.div`
  display: grid;
  grid-template-columns: repeat(4, 1fr); /* 1행 4열 */
  gap: 16px; /* 간격 조정 가능 */
  width: 95%;
  padding: 3%;
  border-radius: 10px;
  background: #e3e3e3;

  /* 모바일 뷰 (768px 이하) */
  @media (max-width: 800px) {
    grid-template-columns: repeat(2, 1fr); /* 2행 2열 */
  }
`;

function App() {
  interface ControlMessage {
    light: boolean;
    w: boolean;
    fan: boolean;
  }

  const socket = useSocket(); // 이렇게 반환 값을 변수에 저장해야 합니다.
  const { hlight, win, fan } = useContext(OnoffContext);

  const [homemode, setHomemode] = useState<string>("홈");
  const [serverTime, setServerTime] = useState("loading");
  const [temp, setTemp] = useState<string>("loading");
  const [humi, setHumi] = useState<string>("loading");
  const [co2, setCo2] = useState<string>("loading");
  const [light, setLight] = useState<string>("loading");
  const [toggle, setToggle] = useState<boolean>(false);

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

  //'message'

  return (
    <Body>
      {toggle && <Over onClick={() => setToggle(false)} />}
      <Global styles={globalStyles} />
      <Sidebar>
        <Sidediv>Smart Home</Sidediv>

        <Sidebutton
          onClick={() => {
            setHomemode("홈");
          }}
          imageSrc="/Home.svg"
        >
          홈
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("모드");
          }}
          imageSrc="/Mode.svg"
        >
          모드
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("센서");
          }}
          imageSrc="/Wind.svg"
        >
          센서
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("제어");
          }}
          imageSrc="/Control.svg"
        >
          제어
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("현관");
          }}
          imageSrc="/Video.svg"
        >
          현관
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("방문객");
          }}
          imageSrc="/User.svg"
        >
          방문객
        </Sidebutton>
      </Sidebar>

      <Mobabar $toggle={toggle}>
        <Sidediv>Smart Home</Sidediv>
        <Sidebutton
          onClick={() => {
            setHomemode("홈");
          }}
          imageSrc="/Home.svg"
        >
          홈
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("모드");
          }}
          imageSrc="/Mode.svg"
        >
          모드
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("센서");
          }}
          imageSrc="/Wind.svg"
        >
          센서
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("제어");
          }}
          imageSrc="/Control.svg"
        >
          제어
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("현관");
          }}
          imageSrc="/Video.svg"
        >
          현관
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("방문객");
          }}
          imageSrc="/User.svg"
        >
          방문객
        </Sidebutton>
      </Mobabar>

      <Main>
        <Titlebar>
          <HomeModeText>{homemode}</HomeModeText>

          <Mobamenu onClick={() => setToggle((prev) => !prev)}>
            <img src="mobatoggle.svg" alt="아이콘" />
          </Mobamenu>
          <Timebar>{serverTime}</Timebar>
        </Titlebar>
        <Div>
          {homemode === "홈" && (
            <div>
              <WeatherDisplay />
              <Grid />
            </div>
          )}

          {homemode === "모드" && (
            <div>
              <Contentbox title="모드" description="집 제어 환경 설정" />
              <Sdiv>
                <Modebox>
                  <ModeButton ttt="수동" />
                  <ModeButton ttt="재실" />
                  <ModeButton ttt="취침" />
                  <ModeButton ttt="외출" />
                </Modebox>
              </Sdiv>
            </div>
          )}

          {homemode === "센서" && (
            <div>
              <Contentbox title="센서" description="집 안 센서 정보" />

              <Tempbox
                temp={temp}
                humi={humi}
                co2={co2}
                light={light}
              ></Tempbox>
            </div>
          )}

          {homemode === "제어" && (
            <div>
              <Contentbox title="제어" description="집 안 장치 제어" />
              <Controlbox />
            </div>
          )}

          {homemode === "현관" && (
            <div>
              <Contentbox title="현관" description="현관 CCTV 관찰" />
              <WebcamStreamClient />
            </div>
          )}

          {homemode === "방문객" && (
            <div>
              <Contentbox
                title="방문객"
                description="현관 CCTV로 방문객 감지"
              />
              <Visit></Visit>
            </div>
          )}
        </Div>
      </Main>
    </Body>
  );
}

export default App;
