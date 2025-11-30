import ModeButton from "../components/layout/Modebutton";
import Contentbox from "../components/layout/Contentbox";
import styled from "@emotion/styled";

const Modebox = styled.div`
  display: grid;
  grid-template-columns: repeat(4, 1fr); /* 1행 4열 */
  gap: 16px; /* 간격 조정 가능 */
  width: 95%;
  padding: 3%;
  border-radius: 10px;
  background: #e3e3e3;

  /* 모바일 뷰 (768px 이하) */
  @media (max-width: 800px) {
    grid-template-columns: repeat(2, 1fr); /* 2행 2열 */
  }
`;
const Sdiv = styled.div`
  margin: 3%;
  background-color: white;
  padding: 3%;
`;
const Mode = () => {
  
  return (
    <div>
      <Contentbox title="모드" description="집 제어 환경 설정" />
      <Sdiv>
        <Modebox>
          <ModeButton ttt="sudong" />
          <ModeButton ttt="in" />
          <ModeButton ttt="zzz" />
          <ModeButton ttt="out" />
        </Modebox>
      </Sdiv>
    </div>
  );
};

export default Mode;
