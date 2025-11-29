import styled from "@emotion/styled";
import { useContext } from "react";
import { OnoffContext } from "../../context/OnoffContext";

const Sbutton = styled.button<{ ttt: string; mode: string }>`
  background: ${(props) => (props.mode == props.ttt ? "#5850ec" : "#E3E3E3")};
  border: none;
  cursor: pointer;
  width: 100%;
  color: ${(props) => (props.mode == props.ttt ? "white" : "#9E9E9E")};
  font-weight: 400;
  font-size: 26.5px;
  border-radius: 10px;
  height: 10vh;
`;

interface ToggleButtonProps {
  ttt: string;
}

const ModeButton = ({ ttt }: ToggleButtonProps) => {
  const { modetype, setModetype } = useContext(OnoffContext);
  return (
    <Sbutton onClick={() => setModetype(ttt)} mode={modetype} ttt={ttt}>
      {ttt}
    </Sbutton>
  );
};

export default ModeButton;
