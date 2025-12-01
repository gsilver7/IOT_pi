import { useState, useMemo } from "react";
import type { FC, ReactNode } from "react";
import { OnoffContext } from "./OnoffContext";

const OnoffContextProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [hlight, setHlight] = useState<number>(0);
  const [glight, setGlight] = useState<number>(0);
  const [win, setWin] = useState<number>(0);
  const [fan, setFan] = useState<number>(0);
  const [hit, setHit] = useState<number>(0);
  const [hum, setHum] = useState<number>(0);
  const [door, setDoor] = useState<number>(0);
  const [serverTime, setServerTime] = useState<string>("loading");
  const [temp, setTemp] = useState<string>("loading");
  const [humi, setHumi] = useState<string>("loading");
  const [co2, setCo2] = useState<string>("loading");
  const [light, setLight] = useState<string>("loading");
  const [python, setPython] = useState<boolean>(false);

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
      python,
      setPython
    }),
    [
      hlight,
      glight,
      win,
      fan,
      hit,
      hum,
      door,
      serverTime,
      temp,
      setTemp,
      humi,
      setHumi,
      co2,
      setCo2,
      light,
      setLight,
      python,
      setPython
    ]
  );

  return (
    <OnoffContext.Provider value={value}>{children}</OnoffContext.Provider>
  );
};

export default OnoffContextProvider;
