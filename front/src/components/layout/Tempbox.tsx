import styled from "@emotion/styled";
import React from 'react';

const Sh2 = styled.h2`
  color: #212121;
  font-size:100%;
  margin:1%;
  margin-bottom:8%;
`;

const Sh3 = styled.h3`
  color:#5850EC;
  text-align: center;
  font-size:160%;
  font-weight:700;
  
`;
const Sdiv = styled.div`
  margin:3%;
  background-color:white;
  padding:3%;
  display:grid;
  grid-template-columns: 1fr 1fr;
  column-gap: 3%;
`;

const Indiv = styled.div`
  border: 1px solid #E6E7E9;
  border-radius: 10px;
  height:200px;
`;

interface Tempbox {
  temp: string;
  co2: string;
}

const Tempbox: React.FC<Tempbox> = ({temp,co2}) => {




  return(
    <Sdiv>
      <Indiv>
        <Sh2>현재 온도</Sh2>
        <Sh3>{temp}</Sh3>
      </Indiv>   
      <Indiv>
        <Sh2>현재 온도</Sh2>
        <Sh3>{co2}</Sh3>
      </Indiv>
    </Sdiv>

  )
}
export default Tempbox;