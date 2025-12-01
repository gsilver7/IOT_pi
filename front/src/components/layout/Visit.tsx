import ToggleImg from './ToggleImg';
import styled from "@emotion/styled";
import ToggleButton from './ToggleButton';
import { OnoffContext } from '../../context/OnoffContext';
import { useContext } from 'react';
import WebcamStreamClient from "../WebcamStreamClient";


const Sh2 = styled.h2`
  color: #212121;
  font-size:100%;
  margin:1%;
`;

const Sdiv = styled.div`
  margin:3%;
  background-color:white;
  padding:3%;
  display:grid;
  grid-template-columns: 1fr 1fr;

  column-gap: 3%;
  height:55vh;

  @media (max-width: 1200px) {
    display: flex;
    flex-direction: column;
    align-items: center;
    height:100vh;
  }
`;

const Indiv = styled.div`
  border: 1px solid #E6E7E9;
  border-radius: 10px;
  margin-bottom:5%;
  position:relative;
  height:25vh;
  @media (max-width: 1200px) {
    
    width:100%;
    height:30vh;
  }
`;
const IndivT = styled.div`
  border: 1px solid #E6E7E9;
  border-radius: 10px;
  margin-bottom:5%;
  position:relative;
  grid-row: span 2;
  
  `;

const Light = () => {

  const {door, setDoor} = useContext(OnoffContext);
  return(      
    <Sdiv>
      <IndivT>
        <Sh2>방문객 사진</Sh2>
        <WebcamStreamClient></WebcamStreamClient>
      </IndivT>   
      <Indiv>
        <Sh2>도어락 제어</Sh2>
          <ToggleImg buttonimg={door ? '/toggle/Dooron.svg' : '/toggle/Dooroff.svg'} ttt={door}></ToggleImg>
        <ToggleButton onClick={() => setDoor((prev) => (prev === 0 ? 1 : 0))} ttt={door}></ToggleButton>
      </Indiv>
    </Sdiv>
  )
}

export default Light;