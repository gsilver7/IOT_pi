import styled from "@emotion/styled";
import React from 'react';

const Sh1 = styled.h1`
  color: #212121;
  margin-bottom:1%;
`;

const Sh2 = styled.h2`
  color:#5850EC;
  font-size:90%;
  font-weight:500;
`;
const Sdiv = styled.div`
  margin:3%;
`;

interface Contentbox {
  title: string;
  description: string;
}

const Contentbox: React.FC<Contentbox> = ({title,description}) => {




  return(
    <Sdiv>
      <Sh1>{title}</Sh1>
      <Sh2>{description}</Sh2>
    </Sdiv>

  )
}
export default Contentbox;