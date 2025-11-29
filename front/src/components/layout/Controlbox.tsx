import ToggleImg from "./ToggleImg";
import styled from "@emotion/styled";
import ToggleButton from "./ToggleButton";
import { OnoffContext } from "../../context/OnoffContext";
import { useContext } from "react";

const Sh2 = styled.h2`
  color: #212121;
  font-size: 100%;
  margin: 1%;
`;

const Sdiv = styled.div`
  margin: 3%;
  background-color: white;
  padding: 3%;
  display: grid;
  grid-template-columns: 1fr 1fr;
  grid-template-rows: 1fr 1fr 0.1fr;
  column-gap: 3%;
  row-gap: 3%;
  height: 90vh;
  @media (max-width: 1000px) {
    height: 60vh;
  }
  @media (max-width: 800px) {
    grid-template-columns: 1fr;
    grid-template-rows: repeat(5, auto);
    height: 170vh;
    row-gap: 1%;
  }
  @media (max-width: 600px) {
    height: 150vh;
  }
  @media (max-width: 400px) {
    height: 100vh;
  }
`;

const Indiv = styled.div`
  border: 1px solid #e6e7e9;
  border-radius: 10px;
  margin-bottom: 5%;
  position: relative;
  height: 25vh;
  @media (max-width: 1200px) {
    height: 18vh;
  }
  @media (max-width: 800px) {
    height: 23vh;
  }
  @media (max-width: 700px) {
    height: 22vh;
  }
  @media (max-width: 580px) {
    height: 21vh;
  }
  @media (max-width: 550px) {
    height: 18vh;
  }
  @media (max-width: 500px) {
    height: 16vh;
  }
  @media (max-width: 400px) {
    height: 13vh;
  }
`;

const Controlbox = () => {
  const {
    hlight,
    setHlight,
    glight,
    setGlight,
    win,
    setWin,
    hum,
    setHum,
    hit,
    setHit,
    fan,
    setFan,
  } = useContext(OnoffContext);
  return (
    <Sdiv>
      <Indiv>
        <Sh2>현관 조명</Sh2>
        <ToggleImg
          buttonimg={hlight ? "/toggle/Lighton.svg" : "/toggle/Lightoff.svg"}
          ttt={hlight}
        ></ToggleImg>
        <ToggleButton
          onClick={() => setHlight((prev) => !prev)}
          ttt={hlight}
        ></ToggleButton>
      </Indiv>
      <Indiv>
        <Sh2>거실 조명</Sh2>
        <ToggleImg
          buttonimg={glight ? "/toggle/Lighton.svg" : "/toggle/Lightoff.svg"}
          ttt={glight}
        ></ToggleImg>
        <ToggleButton onClick={() => setGlight((prev) => !prev)} ttt={glight} />
      </Indiv>
      <Indiv>
        <Sh2>창문</Sh2>
        <ToggleImg
          buttonimg={win ? "/toggle/Windowon.svg" : "/toggle/Windowoff.svg"}
          ttt={win}
        ></ToggleImg>
        <ToggleButton
          onClick={() => setWin((prev) => !prev)}
          ttt={win}
        ></ToggleButton>
      </Indiv>
      <Indiv>
        <Sh2>FAN</Sh2>
        <ToggleImg
          buttonimg={fan ? "/toggle/Windon.svg" : "/toggle/Windoff.svg"}
          ttt={fan}
        ></ToggleImg>
        <ToggleButton
          onClick={() => setFan((prev) => !prev)}
          ttt={fan}
        ></ToggleButton>
      </Indiv>
      <Indiv>
        <Sh2>가습기</Sh2>
        <ToggleImg
          buttonimg={hum ? "/toggle/humon.svg" : "/toggle/humoff.svg"}
          ttt={hum}
        ></ToggleImg>
        <ToggleButton
          onClick={() => setHum((prev) => !prev)}
          ttt={hum}
        ></ToggleButton>
      </Indiv>
      <Indiv>
        <Sh2>발열판</Sh2>
        <ToggleImg
          buttonimg={hit ? "/toggle/hiton.svg" : "/toggle/hitoff.svg"}
          ttt={hit}
        ></ToggleImg>
        <ToggleButton
          onClick={() => setHit((prev) => !prev)}
          ttt={hit}
        ></ToggleButton>
      </Indiv>
    </Sdiv>
  );
};

export default Controlbox;
