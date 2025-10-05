import styled from "@emotion/styled";
import React from 'react';

const Sh2 = styled.h1`
  color: #212121;
  margin-bottom:1%;
`;

const Sh3 = styled.h2`
  color:#5850EC;
  font-size:90%;
  font-weight:500;
`;
const Sdiv = styled.div`
  margin:3%;
  background-color:white;
  padding:3%
`;

const Indiv = styled.div`
  border: 1px solid #E6E7E9;
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