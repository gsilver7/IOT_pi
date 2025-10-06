import styled from "@emotion/styled";

interface SidebuttonProps {
  imageSrc: string;
  children: React.ReactNode;
  onClick: () => void;
}
const Styledbutton = styled.button`
  width: 100%;
  height: 100%;
  background-color:#121620;
  text-align:left;
  color:white;
  border:0;
  padding-left:25%;
cursor: pointer;
`;

const Styledp = styled.p`
  right:10%;
  top:2.5%;
  position:absolute;
  z-index:1;
  user-select: none;
`;

const Stylediv = styled.div`
position: relative;
height: 5%;
  margin-top:1%;
`;

const Styledimg = styled.img`
  position:absolute;
  top:30%;
  left:10%;
  width:10%;

`;


const Sidebutton: React.FC<SidebuttonProps> = ({imageSrc,children,onClick}) => {


  return(
    <Stylediv>
      <Styledbutton onClick={onClick}>
        <Styledimg src={imageSrc} alt="아이콘" />
        {children}
      </Styledbutton>
      <Styledp>&gt;</Styledp>
    </Stylediv>

  )
}
export default Sidebutton;