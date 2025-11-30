import React, { useState } from "react";
import axios from "axios";

const API_URL = "https://kmj.shscript.com/api/auth";

export default function Register() {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    email: "",
    name: "",
    password: "",
  });
  const [verificationCode, setVerificationCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;

    if (name === "password") {
      if (!/^\d*$/.test(value)) {
        setError("비밀번호는 숫자만 입력 가능합니다.");
        return;
      }
    }

    setFormData((prev) => ({ ...prev, [name]: value }));
    setError("");
  };

  const handleSendVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!formData.email || !formData.name || !formData.password) {
      setError("모든 필드를 입력해주세요.");
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      setError("올바른 이메일 형식을 입력해주세요.");
      return;
    }

    if (formData.password.length < 4) {
      setError("비밀번호는 최소 4자리 이상이어야 합니다.");
      return;
    }

    setLoading(true);

    try {
      await axios.post(`${API_URL}/send-verification-email`, {
        email: formData.email,
      });

      setSuccess("인증 코드가 이메일로 발송되었습니다!");
      setStep(2);
    } catch (err) {
      const error = err as { response?: { data?: { message?: string } } };
      setError(error.response?.data?.message || "이메일 발송에 실패했습니다.");
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!verificationCode || verificationCode.length !== 6) {
      setError("6자리 인증 코드를 입력해주세요.");
      return;
    }

    setLoading(true);

    try {
      const verifyResponse = await axios.post(`${API_URL}/verify-code`, {
        email: formData.email,
        code: verificationCode,
      });

      if (!verifyResponse.data.success) {
        setError("인증 코드가 올바르지 않습니다.");
        setLoading(false);
        return;
      }

      await axios.post(`${API_URL}/register`, {
        email: formData.email,
        name: formData.name,
        password: parseInt(formData.password),
        face: "",
        bluetooth: "",
      });

      setSuccess("회원가입이 완료되었습니다!");

      setTimeout(() => {
        window.location.href = "/login";
      }, 3000);
    } catch (err) {
      const error = err as { response?: { data?: { message?: string } } };
      if (
        error.response?.data?.message?.includes("duplicate") ||
        error.response?.data?.message?.includes("이미 존재")
      ) {
        setError("이미 가입된 이메일입니다.");
      } else {
        setError(error.response?.data?.message || "회원가입에 실패했습니다.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleBack = () => {
    setStep(1);
    setVerificationCode("");
    setError("");
    setSuccess("");
  };

  return (
    <div className="register-container">
      <div className="register-card">
        <h1 className="register-title">회원가입</h1>

        {step === 1 && (
          <form onSubmit={handleSendVerification} className="register-form">
            <div className="input-group">
              <label className="input-label">이메일 *</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="example@email.com"
                className="input-field"
                required
              />
            </div>

            <div className="input-group">
              <label className="input-label">이름 *</label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="홍길동"
                className="input-field"
                required
              />
            </div>

            <div className="input-group">
              <label className="input-label">비밀번호 (숫자만) *</label>
              <input
                type="text"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="1234"
                className="input-field"
                maxLength={10}
                required
              />
              <small className="input-hint">숫자만 입력 가능합니다</small>
            </div>

            {error && <div className="message error-message">{error}</div>}
            {success && (
              <div className="message success-message">{success}</div>
            )}

            <button type="submit" className="submit-button" disabled={loading}>
              {loading ? "처리 중..." : "인증 코드 발송"}
            </button>
          </form>
        )}

        {step === 2 && (
          <form onSubmit={handleRegister} className="register-form">
            <div className="info-box">
              <p>
                <strong>{formData.email}</strong>로
              </p>
              <p>인증 코드가 발송되었습니다.</p>
            </div>

            <div className="input-group">
              <label className="input-label">인증 코드 (6자리)</label>
              <input
                type="text"
                value={verificationCode}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, "");
                  if (value.length <= 6) {
                    setVerificationCode(value);
                  }
                }}
                placeholder="123456"
                className="input-field code-input"
                maxLength={6}
                required
              />
            </div>

            {error && <div className="message error-message">{error}</div>}
            {success && (
              <div className="message success-message">{success}</div>
            )}

            <button type="submit" className="submit-button" disabled={loading}>
              {loading ? "처리 중..." : "회원가입 완료"}
            </button>

            <button type="button" onClick={handleBack} className="back-button">
              이전으로
            </button>
          </form>
        )}
      </div>

      <style>{`
        .register-container {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          padding: 20px;
        }

        .register-card {
          background: white;
          border-radius: 12px;
          padding: 40px;
          max-width: 450px;
          width: 100%;
          box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }

        .register-title {
          font-size: 28px;
          font-weight: bold;
          color: #333;
          margin: 0 0 30px 0;
          text-align: center;
        }

        .register-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .input-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .input-label {
          font-size: 14px;
          font-weight: 600;
          color: #555;
        }

        .input-field {
          padding: 12px;
          font-size: 16px;
          border: 2px solid #e0e0e0;
          border-radius: 8px;
          outline: none;
          transition: border-color 0.3s;
        }

        .input-field:focus {
          border-color: #667eea;
        }

        .code-input {
          font-size: 24px;
          text-align: center;
          letter-spacing: 8px;
          font-weight: bold;
        }

        .input-hint {
          font-size: 12px;
          color: #888;
        }

        .submit-button {
          padding: 14px;
          font-size: 16px;
          font-weight: 600;
          color: white;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border: none;
          border-radius: 8px;
          cursor: pointer;
          transition: transform 0.2s;
        }

        .submit-button:hover:not(:disabled) {
          transform: translateY(-2px);
        }

        .submit-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .back-button {
          padding: 12px;
          font-size: 14px;
          font-weight: 600;
          color: #667eea;
          background: white;
          border: 2px solid #667eea;
          border-radius: 8px;
          cursor: pointer;
          transition: background 0.3s;
        }

        .back-button:hover {
          background: #f0f4ff;
        }

        .message {
          padding: 12px;
          border-radius: 8px;
          font-size: 14px;
          text-align: center;
        }

        .error-message {
          background: #fee;
          color: #c33;
        }

        .success-message {
          background: #efe;
          color: #3c3;
        }

        .info-box {
          padding: 16px;
          background: #f0f4ff;
          border-radius: 8px;
          text-align: center;
          color: #555;
        }

        .info-box p {
          margin: 5px 0;
        }
      `}</style>
    </div>
  );
}
