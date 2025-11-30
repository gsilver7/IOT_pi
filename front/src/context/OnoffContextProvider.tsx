import { useState, useMemo } from "react";
import type { FC, ReactNode } from "react";
import { OnoffContext } from "./OnoffContext";

const OnoffContextProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [hlight, setHlight] = useState<boolean>(false);
  const [glight, setGlight] = useState<boolean>(false);
  const [win, setWin] = useState<boolean>(false);
  const [fan, setFan] = useState<boolean>(false);
  const [hit, setHit] = useState<boolean>(false);
  const [hum, setHum] = useState<boolean>(false);
  const [door, setDoor] = useState<boolean>(false);
  const [modetype, setModetype] = useState<string>("수동");
  const [serverTime, setServerTime] = useState<string>("loading");
  const [temp, setTemp] = useState<string>("loading");
  const [humi, setHumi] = useState<string>("loading");
  const [co2, setCo2] = useState<string>("loading");
  const [light, setLight] = useState<string>("loading");

  const value = useMemo(
    () => ({
      hlight,
      setHlight,
      glight,
      setGlight,
      win,
      setWin,
      fan,
      setFan,
      hit,
      setHit,
      hum,
      setHum,
      door,
      setDoor,
      modetype,
      setModetype,
      serverTime,
      setServerTime,
      temp,
      setTemp,
      humi,
      setHumi,
      co2,
      setCo2,
      light,
      setLight,
    }),
    [
      hlight,
      glight,
      win,
      fan,
      hit,
      hum,
      door,
      modetype,
      serverTime,
      temp,
      setTemp,
      humi,
      setHumi,
      co2,
      setCo2,
      light,
      setLight,
    ]
  );

  return (
    <OnoffContext.Provider value={value}>{children}</OnoffContext.Provider>
  );
};

export default OnoffContextProvider;
