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
  column-gap: 3%;
`;

const Indiv = styled.div`
  border: 1px solid #E6E7E9;
  border-radius: 10px;
  height:280px;
  margin-bottom:5%;
  position:relative;
`;

const Light = () => {



  return(

      
    <Sdiv>
      <Indiv>
        <Sh2>현관 조명</Sh2>
        <ToggleImg buttonimg='/toggle/Lightoff.svg'></ToggleImg>
        <ToggleButton></ToggleButton>
      </Indiv>   
      <Indiv>
        <Sh2>거실 조명</Sh2>
        <ToggleImg buttonimg='/toggle/Lightoff.svg'></ToggleImg>
        <ToggleButton></ToggleButton>
      </Indiv>
    </Sdiv>
  )
}

export default Light;