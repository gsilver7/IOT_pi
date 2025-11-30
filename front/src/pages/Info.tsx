import Contentbox from "../components/layout/Contentbox";
import { LogoutButton } from "../components/Logoutbutton";
import BluetoothRegister from "../components/BluetoothRegister";
import { OnoffContext } from "../context/OnoffContext";
import { useContext } from "react";

const Info = () => {


  

  return (
    <div>
      <Contentbox title="정보" description="내 정보 관리" />
      <LogoutButton />
      <BluetoothRegister />
    </div>
  );
};
export default Info;