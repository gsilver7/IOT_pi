import styled from '@emotion/styled';

const Sdiv = styled.div`
  position:absolute;
  top:25%;
  right:13%;
`;

const Sp = styled.p`
  margin:2%;
  color: #9E9E9E;

  text-align:center;
`;

const Sbutton = styled.button`
  background: none; /* 배경을 없앰 */
  border: none;   /* 테두리를 없앰 */
  cursor: pointer;
  `;

const ToggleButton = () => {





  return(
    <Sdiv>
      <Sbutton><img src='/toggle/Off.svg'></img></Sbutton>
      <Sp>정지</Sp>
    </Sdiv>


  )
}

export default ToggleButton;