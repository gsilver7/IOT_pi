import React, { useState } from "react";
import axios from "axios";

// ⚠️ API_URL을 자신의 백엔드 주소로 정확히 설정해야 합니다.
const API_URL = "https://kmj.shscript.com/api/auth";

// DTO 인터페이스 (백엔드와 일치해야 함)
interface FormData {
  email: string;
  name: string;
  password: string; // TypeORM에서 숫자로 저장하더라도 input에서는 string으로 관리
}

// 에러 객체 타입 정의 (AxiosError 처리)
interface AxiosErrorResponse {
  response?: {
    data?: {
      message?: string;
    };
  };
}

export default function Register() {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<FormData>({
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
    let newValue = value;
    let currentError = "";

    // 1. 비밀번호 입력 시 숫자만 허용하는 검증 강화
    if (name === "password") {
      // 숫자 외의 문자는 제거하고, 10자리 제한을 유지
      newValue = value.replace(/\D/g, "");

      // 사용자에게 시각적으로 오류 피드백을 주기 위해, 상태에 반영하지 않더라도 오류 메시지는 설정
      if (value !== newValue) {
        currentError = "비밀번호는 숫자만 입력 가능합니다.";
      }
    }

    // 상태 업데이트 (유효성 검사를 통과한 값 또는 정리된 값으로)
    setFormData((prev) => ({ ...prev, [name]: newValue }));

    // 이전에 발생한 에러는 지우고, 현재 단계에서 발생한 에러만 표시
    setError(currentError);
    setSuccess("");
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
      // 1단계: 인증 코드 발송 요청
      await axios.post(`${API_URL}/send-verification-email`, {
        email: formData.email,
      });

      setSuccess(`인증 코드가 ${formData.email}로 발송되었습니다!`);
      setStep(2); // 다음 단계로 이동
    } catch (err) {
      const error = err as AxiosErrorResponse;
      setError(
        error.response?.data?.message ||
          "이메일 발송에 실패했습니다. (서버/SMTP 설정 확인 필요)"
      );
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
      // 2단계: 인증 코드 검증 요청
      const verifyResponse = await axios.post(`${API_URL}/verify-email`, {
        // ⚠️ 엔드포인트 수정: verify-code -> verify-email (백엔드와 일치하도록 가정)
        email: formData.email,
        code: verificationCode,
      });

      // 3단계: 최종 회원가입 요청 (인증 성공 후)
      // ⚠️ 비밀번호는 백엔드에서 DTO에 맞게 parseInt(string) 처리하므로 string 그대로 전송합니다.
      await axios.post(`${API_URL}/register`, {
        email: formData.email,
        name: formData.name,
        // Number로 변환하여 전송 (백엔드 DTO가 number를 기대할 경우)
        password: parseInt(formData.password, 10),
        // face와 bluetooth는 현재 데이터가 없으므로 빈 문자열 전송
        face: "",
        bluetooth: "",
      });

      setSuccess(
        "회원가입이 완료되었습니다! 3초 후 로그인 페이지로 이동합니다."
      );

      setTimeout(() => {
        // window.location.href = "/login"; // 외부 URL 이동 대신 현재 캔버스 환경에서 라우팅이 필요할 수 있으므로 주석 처리
        console.log("회원가입 완료. 로그인 페이지로 이동 예정.");
      }, 3000);
    } catch (err) {
      const error = err as AxiosErrorResponse;
      const message = error.response?.data?.message;

      if (message?.includes("duplicate") || message?.includes("이미 존재")) {
        setError("이미 가입된 이메일이거나 사용자입니다.");
      } else if (message?.includes("유효하지 않")) {
        setError("인증 코드가 만료되었거나 올바르지 않습니다.");
      } else {
        setError(message || "회원가입 처리 중 알 수 없는 오류가 발생했습니다.");
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

  // Tailwind CSS를 사용하지 않으므로, 내장 CSS로 스타일링 유지
  return (
    <div
      className="flex items-center justify-center min-h-screen bg-gray-100 p-4"
      style={{
        background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
      }}
    >
      <div className="bg-white rounded-xl shadow-2xl p-8 max-w-lg w-full">
        <h1 className="text-3xl font-bold text-gray-800 text-center mb-6">
          회원가입
        </h1>

        {/* Step 1: 정보 입력 및 코드 발송 */}
        {step === 1 && (
          <form
            onSubmit={handleSendVerification}
            className="flex flex-col space-y-5"
          >
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-600">
                이메일 *
              </label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="example@email.com"
                className="w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
                required
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-600">
                이름 *
              </label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="홍길동"
                className="w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
                required
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-600">
                비밀번호 (숫자만) *
              </label>
              <input
                // ⚠️ type="tel"로 변경하여 모바일 숫자 키패드를 유도
                type="tel"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="1234"
                className="w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
                maxLength={10}
                required
              />
              <small className="text-xs text-gray-500">
                숫자만 입력 가능합니다 (최대 10자리)
              </small>
            </div>

            {error && (
              <div className="p-3 bg-red-100 text-red-700 rounded-lg text-sm font-medium">
                {error}
              </div>
            )}
            {success && (
              <div className="p-3 bg-green-100 text-green-700 rounded-lg text-sm font-medium">
                {success}
              </div>
            )}

            <button
              type="submit"
              className="w-full py-3 text-white font-semibold rounded-lg shadow-md transition duration-200 
                         bg-indigo-500 hover:bg-indigo-600 disabled:opacity-60 disabled:cursor-not-allowed"
              disabled={loading || !!error} // 에러가 있을 때도 버튼 비활성화
            >
              {loading ? "처리 중..." : "인증 코드 발송"}
            </button>
          </form>
        )}

        {/* Step 2: 인증 코드 입력 및 가입 완료 */}
        {step === 2 && (
          <form onSubmit={handleRegister} className="flex flex-col space-y-5">
            <div className="p-4 bg-indigo-50 border border-indigo-200 rounded-lg text-center text-sm text-gray-700">
              <p className="font-semibold">{formData.email}</p>
              <p>로 6자리 인증 코드가 발송되었습니다.</p>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-600">
                인증 코드 (6자리)
              </label>
              <input
                type="tel" // 6자리 코드 입력 시 숫자 키패드 유도
                value={verificationCode}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, "");
                  if (value.length <= 6) {
                    setVerificationCode(value);
                  }
                }}
                placeholder="123456"
                className="w-full p-3 border border-gray-300 rounded-lg text-center text-xl font-bold tracking-widest focus:ring-indigo-500 focus:border-indigo-500"
                maxLength={6}
                required
              />
            </div>

            {error && (
              <div className="p-3 bg-red-100 text-red-700 rounded-lg text-sm font-medium">
                {error}
              </div>
            )}
            {success && (
              <div className="p-3 bg-green-100 text-green-700 rounded-lg text-sm font-medium">
                {success}
              </div>
            )}

            <button
              type="submit"
              className="w-full py-3 text-white font-semibold rounded-lg shadow-md transition duration-200 
                         bg-indigo-500 hover:bg-indigo-600 disabled:opacity-60 disabled:cursor-not-allowed"
              disabled={loading || verificationCode.length !== 6}
            >
              {loading ? "처리 중..." : "회원가입 완료"}
            </button>

            <button
              type="button"
              onClick={handleBack}
              className="w-full py-2 text-indigo-500 border border-indigo-500 bg-white hover:bg-indigo-50 rounded-lg font-medium transition duration-200"
            >
              이전 정보 수정
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
