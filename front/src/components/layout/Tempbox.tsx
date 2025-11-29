import styled from "@emotion/styled";
import React from "react";

const Sh2 = styled.h2`
  color: #212121;
  font-size: 100%;
  margin: 1%;
  margin-bottom: 8%;
`;

const Sh3 = styled.h3`
  color: #5850ec;
  text-align: center;
  font-size: 160%;
  font-weight: 700;
`;
const Sdiv = styled.div`
  margin: 3%;
  background-color: white;
  padding: 3%;
  display: grid;
  grid-template-columns: 1fr 1fr;
  grid-template-rows: 1fr 1fr 0.1fr;
  column-gap: 3%;
  row-gap: 5%;

  @media (max-width: 800px) {
    grid-template-columns: 1fr;
    grid-template-rows: repeat(4, 1fr);
    height: 1000px;
  }
`;

const Indiv = styled.div`
  border: 1px solid #e6e7e9;
  border-radius: 10px;
  height: 200px;
`;

interface Tempbox {
  temp: string;
  humi: string;
  co2: string;
  light: string;
}

const Tempbox: React.FC<Tempbox> = ({ temp, humi, co2, light }) => {
  return (
    <Sdiv>
      <Indiv>
        <Sh2>현재 온도</Sh2>
        <Sh3>{temp}</Sh3>
      </Indiv>
      <Indiv>
        <Sh2>현재 습도</Sh2>
        <Sh3>{humi}</Sh3>
      </Indiv>
      <Indiv>
        <Sh2>현재 co2</Sh2>
        <Sh3>{co2}</Sh3>
      </Indiv>
      <Indiv>
        <Sh2>현재 조도</Sh2>
        <Sh3>{light}</Sh3>
      </Indiv>
    </Sdiv>
  );
};
export default Tempbox;
