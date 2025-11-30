import { createContext } from "react";
import type { Dispatch, SetStateAction } from "react";

export interface OnoffContextType {
  hlight: number;
  setHlight: Dispatch<SetStateAction<number>>;
  glight: number;
  setGlight: Dispatch<SetStateAction<number>>;
  win: number;
  setWin: Dispatch<SetStateAction<number>>;
  hum: number;
  setHum: Dispatch<SetStateAction<number>>;
  hit: number;
  setHit: Dispatch<SetStateAction<number>>;
  fan: number;
  setFan: Dispatch<SetStateAction<number>>;
  door: number;
  setDoor: Dispatch<SetStateAction<number>>;
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
  hlight: 0,
  setHlight: () => {},
  glight: 0,
  setGlight: () => {},
  win: 0,
  setWin: () => {},
  hum: 0,
  setHum: () => {},
  hit: 0,
  setHit: () => {},
  fan: 0,
  setFan: () => {},
  door: 0,
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
