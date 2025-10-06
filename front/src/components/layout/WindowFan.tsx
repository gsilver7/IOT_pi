import ToggleImg from './ToggleImg';
import styled from "@emotion/styled";
import ToggleButton from './ToggleButton';

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



  return(

      
    <Sdiv>
      <Th2>창문 제어</Th2>
      <Indiv>
        <Sh2>창문 1</Sh2>
        <ToggleImg buttonimg='/toggle/Windowoff.svg'></ToggleImg>
        <ToggleButton></ToggleButton>
      </Indiv>   
      <Indiv>
        <Sh2>창문 2</Sh2>
        <ToggleImg buttonimg='/toggle/Windowoff.svg'></ToggleImg>
        <ToggleButton></ToggleButton>
      </Indiv>
      <Th2>FAN 제어</Th2>
      <Indiv>
        <Sh2>FAN 1</Sh2>
        <ToggleImg buttonimg='/toggle/Windoff.svg'></ToggleImg>
        <ToggleButton></ToggleButton>
      </Indiv>
      <Indiv>
        <Sh2>FAN 2</Sh2>
        <ToggleImg buttonimg='/toggle/Windoff.svg'></ToggleImg>
        <ToggleButton></ToggleButton>
      </Indiv>
    </Sdiv>
  )
}

export default WindowFan;