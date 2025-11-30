import React, { useState } from 'react';
import axios from 'axios';

const API_URL = 'https://kmj.shscript.com/api/auth';

export default function Register() {
  const [step, setStep] = useState(1); // 1: 정보입력, 2: 이메일 인증
  const [formData, setFormData] = useState({
    email: '',
    name: '',
    password: '',
  });
  const [verificationCode, setVerificationCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 입력값 변경 핸들러
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    
    // password는 숫자만 허용
    if (name === 'password') {
      if (!/^\d*$/.test(value)) {
        setError('비밀번호는 숫자만 입력 가능합니다.');
        return;
      }
    }
    
    setFormData(prev => ({ ...prev, [name]: value }));
    setError('');
  };

  // Step 1: 정보 입력 후 이메일 인증 요청
  const handleSendVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // 유효성 검사
    if (!formData.email || !formData.name || !formData.password) {
      setError('모든 필드를 입력해주세요.');
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      setError('올바른 이메일 형식을 입력해주세요.');
      return;
    }

    if (formData.password.length < 4) {
      setError('비밀번호는 최소 4자리 이상이어야 합니다.');
      return;
    }

    setLoading(true);

    try {
      await axios.post(`${API_URL}/send-verification-email`, {
        email: formData.email,
      });
      
      setSuccess('인증 코드가 이메일로 발송되었습니다!');
      setStep(2);
    } catch (err: any) {
      setError(err.response?.data?.message || '이메일 발송에 실패했습니다.');
    } finally {
      setLoading(false);
    }
  };

  // Step 2: 인증 코드 확인 및 회원가입
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!verificationCode || verificationCode.length !== 6) {
      setError('6자리 인증 코드를 입력해주세요.');
      return;
    }

    setLoading(true);

    try {
      // 1. 인증 코드 검증
      const verifyResponse = await axios.post(`${API_URL}/verify-code`, {
        email: formData.email,
        code: verificationCode,
      });

      if (!verifyResponse.data.success) {
        setError('인증 코드가 올바르지 않습니다.');
        setLoading(false);
        return;
      }

      // 2. 회원가입
      await axios.post(`${API_URL}/register`, {
        email: formData.email,
        name: formData.name,
        password: parseInt(formData.password),
        face: '', // 빈 값
        bluetooth: '', // 빈 값
      });

      setSuccess('회원가입이 완료되었습니다!');
      
      // 3초 후 로그인 페이지로 이동 (필요시)
      setTimeout(() => {
        window.location.href = '/login';
      }, 3000);
    } catch (err: any) {
      if (err.response?.data?.message?.includes('duplicate') || 
          err.response?.data?.message?.includes('이미 존재')) {
        setError('이미 가입된 이메일입니다.');
      } else {
        setError(err.response?.data?.message || '회원가입에 실패했습니다.');
      }
    } finally {
      setLoading(false);
    }
  };

  // 이전 단계로
  const handleBack = () => {
    setStep(1);
    setVerificationCode('');
    setError('');
    setSuccess('');
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>회원가입</h1>

        {/* Step 1: 정보 입력 */}
        {step === 1 && (
          <form onSubmit={handleSendVerification} style={styles.form}>
            <div style={styles.inputGroup}>
              <label style={styles.label}>이메일 *</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="example@email.com"
                style={styles.input}
                required
              />
            </div>

            <div style={styles.inputGroup}>
              <label style={styles.label}>이름 *</label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="홍길동"
                style={styles.input}
                required
              />
            </div>

            <div style={styles.inputGroup}>
              <label style={styles.label}>비밀번호 (숫자만) *</label>
              <input
                type="text"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="1234"
                style={styles.input}
                maxLength={10}
                required
              />
              <small style={styles.hint}>숫자만 입력 가능합니다</small>
            </div>

            {error && <div style={styles.error}>{error}</div>}
            {success && <div style={styles.success}>{success}</div>}

            <button 
              type="submit" 
              style={styles.button}
              disabled={loading}
            >
              {loading ? '처리 중...' : '인증 코드 발송'}
            </button>
          </form>
        )}

        {/* Step 2: 이메일 인증 */}
        {step === 2 && (
          <form onSubmit={handleRegister} style={styles.form}>
            <div style={styles.infoBox}>
              <p><strong>{formData.email}</strong>로</p>
              <p>인증 코드가 발송되었습니다.</p>
            </div>

            <div style={styles.inputGroup}>
              <label style={styles.label}>인증 코드 (6자리)</label>
              <input
                type="text"
                value={verificationCode}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, '');
                  if (value.length <= 6) {
                    setVerificationCode(value);
                  }
                }}
                placeholder="123456"
                style={{...styles.input, ...styles.codeInput}}
                maxLength={6}
                required
              />
            </div>

            {error && <div style={styles.error}>{error}</div>}
            {success && <div style={styles.success}>{success}</div>}

            <button 
              type="submit" 
              style={styles.button}
              disabled={loading}
            >
              {loading ? '처리 중...' : '회원가입 완료'}
            </button>

            <button 
              type="button" 
              onClick={handleBack}
              style={styles.backButton}
            >
              이전으로
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    padding: '20px',
  },
  card: {
    background: 'white',
    borderRadius: '12px',
    padding: '40px',
    maxWidth: '450px',
    width: '100%',
    boxShadow: '0 10px 40px rgba(0,0,0,0.2)',
  },
  title: {
    fontSize: '28px',
    fontWeight: 'bold',
    color: '#333',
    marginBottom: '30px',
    textAlign: 'center',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  label: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#555',
  },
  input: {
    padding: '12px',
    fontSize: '16px',
    border: '2px solid #e0e0e0',
    borderRadius: '8px',
    outline: 'none',
    transition: 'border-color 0.3s',
  },
  codeInput: {
    fontSize: '24px',
    textAlign: 'center',
    letterSpacing: '8px',
    fontWeight: 'bold',
  },
  hint: {
    fontSize: '12px',
    color: '#888',
  },
  button: {
    padding: '14px',
    fontSize: '16px',
    fontWeight: '600',
    color: 'white',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    transition: 'transform 0.2s',
  },
  backButton: {
    padding: '12px',
    fontSize: '14px',
    fontWeight: '600',
    color: '#667eea',
    background: 'white',
    border: '2px solid #667eea',
    borderRadius: '8px',
    cursor: 'pointer',
  },
  error: {
    padding: '12px',
    background: '#fee',
    color: '#c33',
    borderRadius: '8px',
    fontSize: '14px',
    textAlign: 'center',
  },
  success: {
    padding: '12px',
    background: '#efe',
    color: '#3c3',
    borderRadius: '8px',
    fontSize: '14px',
    textAlign: 'center',
  },
  infoBox: {
    padding: '16px',
    background: '#f0f4ff',
    borderRadius: '8px',
    textAlign: 'center',
    color: '#555',
  },
};