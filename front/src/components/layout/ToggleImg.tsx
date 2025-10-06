import styled from '@emotion/styled';

interface ToggleImg{
  buttonimg:string;
  ttt:boolean;
}

const Circle = styled.div<{ttt:boolean}>`
  background-color: ${props => props.ttt ? '#CDCBFA' : '#E3E3E3'};
  border-radius: 50%;
  aspect-ratio: 1;
  width: 25%;
  margin:4%;
  position:absolute;
  left:3%;
`;
const Simg = styled.img`
  width:60%;
  padding:20%;
  aspect-ratio: 1;
`;

const ToggleImg: React.FC<ToggleImg> = ({buttonimg, ttt }) => {




  return(
    <div>
      <Circle ttt={ttt}><Simg src={buttonimg}></Simg></Circle>

    </div>

  )
}

export default ToggleImg;