import styled from '@emotion/styled';

const Sdiv = styled.div`
  position:absolute;
  top:25%;
  right:13%;
  width:40%;
`;

const Sp = styled.p<{ttt:boolean}>`
  margin:2%;
  color: ${props => props.ttt ? '#5850EC' : '#9E9E9E'};
  text-align:center;
`;



const Sbutton = styled.button`
  background: none; /* 배경을 없앰 */
  border: none;   /* 테두리를 없앰 */
  cursor: pointer;
  width:100%;
  
  `;
const Simg = styled.img`
  width:100%; 
`;
interface ToggleButtonProps {

  onClick: () => void;
  ttt: boolean;
}

const ToggleButton = ({onClick, ttt}: ToggleButtonProps) => {

  return(
    <Sdiv>
      <Sbutton onClick={onClick}><Simg src={ttt ? '/toggle/On.svg' : '/toggle/Off.svg'}></Simg></Sbutton>
      <Sp ttt={ttt}>{ttt ? '작동중...' : '정지'}</Sp>
    </Sdiv>
  )
}

export default ToggleButton;