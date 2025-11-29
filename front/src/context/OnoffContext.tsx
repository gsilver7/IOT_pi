import { createContext } from "react";
import type { Dispatch, SetStateAction } from "react";

export interface OnoffContextType {
  hlight: boolean;
  setHlight: Dispatch<SetStateAction<boolean>>;
  glight: boolean;
  setGlight: Dispatch<SetStateAction<boolean>>;
  win: boolean;
  setWin: Dispatch<SetStateAction<boolean>>;
  hum: boolean;
  setHum: Dispatch<SetStateAction<boolean>>;
  hit: boolean;
  setHit: Dispatch<SetStateAction<boolean>>;
  fan: boolean;
  setFan: Dispatch<SetStateAction<boolean>>;
  door: boolean;
  setDoor: Dispatch<SetStateAction<boolean>>;
  modetype: string;
  setModetype: Dispatch<SetStateAction<string>>;
}

export const OnoffContext = createContext<OnoffContextType>({
  hlight: false,
  setHlight: () => {},
  glight: false,
  setGlight: () => {},
  win: false,
  setWin: () => {},
  hum: false,
  setHum: () => {},
  hit: false,
  setHit: () => {},
  fan: false,
  setFan: () => {},
  door: false,
  setDoor: () => {},
  modetype: "수동",
  setModetype: () => {},
});
