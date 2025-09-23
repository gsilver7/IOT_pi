import React, { useState } from 'react';
import SocketManager from './SocketManager'; // 수정되지 않은 SocketManager를 그대로 사용합니다.

const MyChatComponent = () => {
  const [inputText, setInputText] = useState('');
  const [sendMessagePayload, setSendMessagePayload] = useState(null);

  const handleSendMessage = () => {
    if (inputText.trim() === '') return;

    // 보낼 메시지를 객체로 만들고, 타임스탬프를 추가하여 매번 새로운 객체를 생성합니다.
    const newPayload = {
      text: inputText,
      timestamp: new Date().getTime(), // 고유성을 보장하는 타임스탬프
    };

    setSendMessagePayload(newPayload); // 이 상태가 업데이트되면 SocketManager의 sendMessage prop이 변경됩니다.
    setInputText('');
  };

  return (
    <div>
      <input
        type="text"
        value={inputText}
        onChange={(e) => setInputText(e.target.value)}
      />
      <button onClick={handleSendMessage}>
        메시지 전송
      </button>

      {/* SocketManager에 객체 형태의 sendMessagePayload를 prop으로 전달합니다. */}
      {/* 이 객체는 타임스탬프 덕분에 매번 새로운 참조를 갖습니다. */}
      <SocketManager url="http://localhost:4000" sendMessage={sendMessagePayload} />
    </div>
  );
};

export default MyChatComponent;