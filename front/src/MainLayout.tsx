import styled from "@emotion/styled";
import Sidebutton from "./components/layout/Sidebutton";
import { useNavigate, Outlet } from "react-router-dom";
import { OnoffContext } from "./context/OnoffContext";
import { useContext } from "react";

const Sidediv = styled.div`
  height: 6%;
  user-select: none;
  padding-left: 12%;
  padding-top: 12%;
  font-weight: 700;
  font-size: 130%;
  @media (max-height: 800px) {
    font-size: 100%;
  }
`;
const Main = styled.div`
  position: relative;
  top: 7%;
  width: 100%;
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
const Sidebar = styled.div`
  border: 0;
  padding: 0;
  color: white;
  border: none;
  height: 100%;
  width: 13%;
  float: left;
  background: #1a202e;
  position: fixed;
  @media (max-width: 800px) {
    display: none;
  }
  z-index: 10;
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
const Timebar = styled.div`
  margin-left: auto;
  margin-right: 0;
  padding: 0;
  padding-right: 30%;
  @media (max-width: 800px) {
    font-size: 20px;
    padding-right: 6%;
  }
  @media (max-width: 400px) {
    font-size: 12px;
    padding-right: 5%;
  }
`;

const ContentArea = styled.div`
  position: relative;
  left: 13%;
  top: 8%;
  width: 87%;
  /* 모바일 대응: 사이드바가 없어지면 꽉 채우기 */
  @media (max-width: 800px) {
    margin-left: 0;
    width: 100%;
    left: 0;
  }
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

const Div = styled.div`
  width: 100%;
  height: 100%;
  position: flex;
  flex-direction: row; /* 가로 방향 배치 */
`;
const MainLayout = ({
  toggle,
  setToggle,
  homemode,
  setHomemode,
}: {
  toggle: boolean;
  homemode: string;
  setToggle: React.Dispatch<React.SetStateAction<boolean>>;
  setHomemode: React.Dispatch<React.SetStateAction<string>>;
}) => {
  const navigate = useNavigate();
  const { serverTime } = useContext(OnoffContext);
  return (
    <Div>
      {" "}
      {toggle && <Over onClick={() => setToggle(false)} />}
      <Sidebar>
        <Sidediv>Smart Home</Sidediv>

        <Sidebutton
          onClick={() => {
            setHomemode("홈");
            navigate("/");
          }}
          imageSrc="/Home.svg"
        >
          홈
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("모드");
            navigate("/mode");
          }}
          imageSrc="/Mode.svg"
        >
          모드
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("센서");
            navigate("/sensor");
          }}
          imageSrc="/Wind.svg"
        >
          센서
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("제어");
            navigate("/control");
          }}
          imageSrc="/Control.svg"
        >
          제어
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("현관");
            navigate("/door");
          }}
          imageSrc="/Video.svg"
        >
          현관
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("방문객");
            navigate("/visitor");
          }}
          imageSrc="/User.svg"
        >
          방문객
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("정보");
            navigate("/info");
          }}
          imageSrc="/User.svg"
        >
          정보
        </Sidebutton>
      </Sidebar>
      <Mobabar $toggle={toggle}>
        <Sidediv>Smart Home</Sidediv>
        <Sidebutton
          onClick={() => {
            setHomemode("홈");
            navigate("/");
          }}
          imageSrc="/Home.svg"
        >
          홈
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("모드");
            navigate("/mode");
          }}
          imageSrc="/Mode.svg"
        >
          모드
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("센서");
            navigate("/sensor");
          }}
          imageSrc="/Wind.svg"
        >
          센서
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("제어");
            navigate("/control");
          }}
          imageSrc="/Control.svg"
        >
          제어
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("현관");
            navigate("/door");
          }}
          imageSrc="/Video.svg"
        >
          현관
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("방문객");
            navigate("/visitor");
          }}
          imageSrc="/User.svg"
        >
          방문객
        </Sidebutton>
        <Sidebutton
          onClick={() => {
            setHomemode("정보");
            navigate("/info");
          }}
          imageSrc="/User.svg"
        >
          정보
        </Sidebutton>
      </Mobabar>
      <ContentArea>
        <Titlebar>
          <HomeModeText>{homemode}</HomeModeText>

          <Mobamenu onClick={() => setToggle((prev) => !prev)}>
            <img src="mobatoggle.svg" alt="아이콘" />
          </Mobamenu>
          <Timebar>{serverTime}</Timebar>
        </Titlebar>
        <Main>
          <Outlet />
        </Main>
      </ContentArea>
    </Div>
  );
};

export default MainLayout;
