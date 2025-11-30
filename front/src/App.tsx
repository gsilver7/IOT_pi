// App.js
import Contentbox from "./components/layout/Contentbox";
import Tempbox from "./components/layout/Tempbox";
import { OnoffContext } from "./context/OnoffContext";
import { useContext } from "react";

function App() {
  // 커스텀 훅을 사용해 데이터만 쏙 가져옵니다.
  const { temp, humi, co2, light } = useContext(OnoffContext);

  return (
    <div>
      <Contentbox title="센서" description="집 안 센서 정보" />

      {/* 가져온 데이터를 UI에 전달 */}
      <Tempbox temp={temp} humi={humi} co2={co2} light={light} />
    </div>
  );
}

export default App;
