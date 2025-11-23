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
  column-gap: 3%;
  height:28vh;
`;

const Indiv = styled.div`
  border: 1px solid #E6E7E9;
  border-radius: 10px;
  margin-bottom:5%;
  position:relative;
`;

const Light = () => {
  const {hlight, setHlight,glight, setGlight} = useContext(OnoffContext);
  return(      
    <Sdiv>
      <Indiv>
        <Sh2>현관 조명</Sh2>
        <ToggleImg buttonimg={hlight ? '/toggle/Lighton.svg' : '/toggle/Lightoff.svg'} ttt={hlight}></ToggleImg>
        <ToggleButton onClick={()=>setHlight(prev => !prev)} ttt={hlight}></ToggleButton>
      </Indiv>   
      <Indiv>
        <Sh2>거실 조명</Sh2>
        <ToggleImg buttonimg={glight ? '/toggle/Lighton.svg' : '/toggle/Lightoff.svg'} ttt={glight}></ToggleImg>
        <ToggleButton onClick={()=>setGlight(prev => !prev)} ttt={glight}></ToggleButton>
      </Indiv>
    </Sdiv>
  )
}

export default Light;