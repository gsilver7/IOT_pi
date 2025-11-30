import Contentbox from "../components/layout/Contentbox";
import Visit from "../components/layout/Visit";

const Visitor = () => {
  return (
    <div>
      <Contentbox title="방문객" description="현관 CCTV로 방문객 감지" />
      <Visit></Visit>
    </div>
  );
};
export default Visitor;
