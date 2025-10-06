import ToggleImg from './ToggleImg';
import styled from "@emotion/styled";
import ToggleButton from './ToggleButton';
import { OnoffContext } from '../../context/OnoffContext';
import { useContext } from 'react';

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
  grid-template-rows: 0.3fr 1fr 0.3fr 1fr;
  column-gap: 3%;
`;

const Indiv = styled.div`
  border: 1px solid #E6E7E9;
  border-radius: 10px;
  height:280px;
  margin-bottom:5%;
  position:relative;
`;

const Th2 = styled.h2`
  grid-column: span 2;
  color: #5850EC;
  font-size:120%;
  margin-bottom:2%;
  `;
const WindowFan = () => {
  const {w1,setW1,w2,setW2,fan1,setFan1,fan2,setFan2} = useContext(OnoffContext);

  return(

      
    <Sdiv>
      <Th2>창문 제어</Th2>
      <Indiv>
        <Sh2>창문 1</Sh2>
        <ToggleImg buttonimg={w1 ? '/toggle/Windowon.svg' : '/toggle/Windowoff.svg'} ttt={w1}></ToggleImg>
        <ToggleButton onClick={()=>setW1(prev => !prev)} ttt={w1}></ToggleButton>
      </Indiv>   
      <Indiv>
        <Sh2>창문 2</Sh2>
        <ToggleImg buttonimg={w2 ? '/toggle/Windowon.svg' : '/toggle/Windowoff.svg'} ttt={w2}></ToggleImg>
        <ToggleButton onClick={()=>setW2(prev => !prev)} ttt={w2}></ToggleButton>
      </Indiv>
      <Th2>FAN 제어</Th2>
      <Indiv>
        <Sh2>FAN 1</Sh2>
        <ToggleImg buttonimg={fan1 ? '/toggle/Windon.svg' : '/toggle/Windoff.svg'} ttt={fan1}></ToggleImg>
        <ToggleButton onClick={()=>setFan1(prev => !prev)} ttt={fan1}></ToggleButton>
      </Indiv>
      <Indiv>
        <Sh2>FAN 2</Sh2>
        <ToggleImg buttonimg={fan2 ? '/toggle/Windon.svg' : '/toggle/Windoff.svg'} ttt={fan2}></ToggleImg>
        <ToggleButton onClick={()=>setFan2(prev => !prev)} ttt={fan2}></ToggleButton>
      </Indiv>
    </Sdiv>
  )
}

export default WindowFan;