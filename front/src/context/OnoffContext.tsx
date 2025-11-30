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
  serverTime: string;
  setServerTime: Dispatch<SetStateAction<string>>;
  temp: string;
  setTemp: Dispatch<SetStateAction<string>>;
  humi: string;
  setHumi: Dispatch<SetStateAction<string>>;
  co2: string;
  setCo2: Dispatch<SetStateAction<string>>;
  light: string;
  setLight: Dispatch<SetStateAction<string>>;
  python: boolean;
  setPython: Dispatch<SetStateAction<boolean>>;
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
  modetype: "sudong",
  setModetype: () => {},
  serverTime: "loading",
  setServerTime: () => {},
  temp: "loading",
  setTemp: () => {},
  humi: "loaging",
  setHumi: () => {},
  co2: "loaging",
  setCo2: () => {},
  light: "loaging",
  setLight: () => {},
  python: false,
  setPython: () => {},
});
