const express = require('express');
const app = express();
const PORT = 4000;

app.use(express.json());

// 테스트용 API 엔드포인트
app.get('/api', (req, res) => {
  res.json({ message: 'Test server is running!' });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/test', (req, res) => {
  res.json({
    message: 'This is a test endpoint',
    data: {
      server: 'iot-pi-server',
      port: PORT
    }
  });
});

app.post('/api/test', (req, res) => {
  res.json({
    message: 'POST request received',
    body: req.body
  });
});

app.listen(PORT, () => {
  console.log(`Test server is running on port ${PORT}`);
});
