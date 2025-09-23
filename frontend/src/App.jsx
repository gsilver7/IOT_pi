// App.js
import { RecoilRoot } from 'recoil';
import SocketManager from './SocketManager';

const socketUrl = 'http://localhost:4000';

function App() {
  return (
    <RecoilRoot>
      <div>
        <h1>front end</h1>
      </div>
    </RecoilRoot>
  );
}

export default App;