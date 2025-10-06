import styled from '@emotion/styled';
import React from 'react';

// 서버의 기본 URL을 상수로 정의
const API_URL = 'http://localhost:4000'; 

// props의 타입을 명시적으로 정의합니다.
interface WriteButtonProps {
    data: string;
    label: string;
}

const Styledbutton = styled.button`
    height:100px;
    width:100px;
    margin:50px;
    border-radius: 8px; /* 모든 모서리를 8px만큼 둥글게 */
    transition: background-color 0.2s, transform 0.1s;
    :hover {
    background-color: #d22ea6ff; /* 색상 어둡게 변경 */
    }
:active {
  background-color: #ff0000ff; /* 더 어둡게 변경 */
  transform: translateY(1px); /* 아래로 살짝 내려가는 효과 */
}
`;


const WriteButton: React.FC<WriteButtonProps> = ({ data, label }) => {
    const handleClick = async () => {
        try {
            // URL에 data를 동적으로 포함하여 GET 요청을 보냅니다.
            const response = await fetch(`${API_URL}/serial/write/${data}`);
            
            if (!response.ok) {
                // HTTP 상태 코드가 200번대가 아닐 경우 에러를 발생시킵니다.
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            
        } catch (error) {
            console.error('Failed to send data:', error);
        }
    };

    return (
        <Styledbutton onClick={handleClick}>
            {label}
        </Styledbutton>
    );
};

export default WriteButton;