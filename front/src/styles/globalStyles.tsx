import { css } from '@emotion/react';
const globalStyles = css`
  html, body {
   -webkit-user-select: none; /* Chrome, Safari, Opera */
  -moz-user-select: none;    /* Firefox */
  -ms-user-select: none;     /* IE/Edge */
  user-select: none;         /* Standard */
    width: 100%;
    margin: 0;
    padding: 0;
    font-family: Arial, sans-serif;
    background-color: #F1F5F9;
    
  }
    
  #root {
    height: 100%;
    width: 100%;
    display: flex;
  }

  h1, h2, h3, h4, h5, h6 {
    color: #333;
    margin: 0;
    padding: 0;
    font-weight: bold;
  }
  main {
  overflow: scroll;
  position:relative;
  left: 13%;
  width: 87%;
  height: 100%;
  padding-top:3%;

     /* Firefox용 스크롤바 숨김 */
    scrollbar-width: none;
  
    /* IE, Edge용 스크롤바 숨김 */
    -ms-overflow-style: none; 
    }

    body::-webkit-scrollbar {
    display: none;
  }

  // 모든 링크에 밑줄 제거
  a {
    text-decoration: none;
    color: inherit;
  }
`;

export default globalStyles;