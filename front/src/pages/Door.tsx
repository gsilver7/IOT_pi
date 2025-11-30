import Contentbox from "../components/layout/Contentbox";
import WebcamStreamClient from "../components/WebcamStreamClient";

const Door = () => {
  return (
    <div>
      <Contentbox title="현관" description="현관 CCTV 관찰" />
      <WebcamStreamClient />
    </div>
  );
};

export default Door;
