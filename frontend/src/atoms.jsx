import { atom } from 'recoil';

export const socketState = atom({
  key: 'socketState',
  default: null,
  dangerouslyAllowMutability: true, // Socket objects are mutable
});

export const messageState = atom({
  key: 'messageState',
  default: [],
});