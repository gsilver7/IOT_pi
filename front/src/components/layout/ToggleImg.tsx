import styled from '@emotion/styled';

interface ToggleImg{
  buttonimg:string;

}

const Circle = styled.div`
  background-color:#E3E3E3;
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

const ToggleImg: React.FC<ToggleImg> = ({buttonimg}) => {




  return(
    <div>
      <Circle><Simg src={buttonimg}></Simg></Circle>

    </div>

  )
}

export default ToggleImg;