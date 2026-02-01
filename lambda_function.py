import json
import boto3
import os
import datetime
import requests
# import google.generativeai as genai
import re
from datetime import timezone, timedelta
from openai import OpenAI

# AWS 클라이언트 초기화
ssm_client = boto3.client('ssm')
sns_client = boto3.client('sns')

# 환경 변수에서 설정 값 불러오기
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
UPSTAGE_API_KEY_PARAMETER_NAME = os.environ.get('UPSTAGE_API_KEY_PARAMETER_NAME')
# GEMINI_API_KEY_PARAMETER_NAME = os.environ.get('GEMINI_API_KEY_PARAMETER_NAME')
LOKI_URL = os.environ.get('LOKI_URL')

# 분석할 로그 그룹 이름들
LOKI_JOB_LABELS_TO_ANALYZE = ['springboot-app-logs', 'codedeploy-agent-logs']

# Gemini API 키 로드
def get_api_key():
    try:
        response = ssm_client.get_parameter(Name=UPSTAGE_API_KEY_PARAMETER_NAME, WithDecryption=True)
        return response['Parameter']['Value']
    except Exception as e:
        print(f"Error retrieving API Key: {e}")
        raise e

# === 전문가용 Gemini 설정 시작 ===

# 1. Upstage 클라이언트 초기화
UPSTAGE_API_KEY = get_api_key()
client = OpenAI(
    api_key=UPSTAGE_API_KEY,
    base_url="https://api.upstage.ai/v1"
)

# 2. JSON 출력 스키마 정의
JSON_SCHEMA = {
  "type":"object",
  "properties":{
    "time_window":{"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"}},"required":["from","to"]},
    "incidents":{"type":"array"},
    "summary_md":{"type":"string"},
    "confidence_overall":{"type":"number"}
  },
  "required":["time_window","incidents","summary_md","confidence_overall"]
}

# 3. 시스템 프롬프트 구성 (JSON 스키마를 텍스트로 포함)
SYSTEM_INSTRUCTION = f"""
당신은 SRE 팀을 위한 로그 분석 AI입니다.
목표: 주어진 로그만으로 사건(incident)을 감지하고, 유사 로그를 하나로 묶어(지문/패턴) 요약하며, 영향도·가설·다음 조치·조회용 질의를 제시합니다.

규칙:
- 외부 지식 추정 금지. 주어진 로그 범위 내에서만 판단.
- 불확실하면 "불확실"로 표기하고 confidence를 낮게 설정.
- 엔터티 정규화: service, env, region, host, error_code.
- 지문(fingerprint)은 변수값 마스킹(예: ID/IP 등) 후 간결하게.
- 샘플 로그(sample_logs)는 3개 이하, 비밀키/토큰/개인정보는 마스킹.
- 한국어로 작성.

[중요] 반드시 다음 JSON 형식을 준수하여 응답해야 합니다:
{json.dumps(JSON_SCHEMA, ensure_ascii=False)}
"""

# 4. Upstage 호출 함수
def call_upstage_json(prompt: str) -> str:
    try:
        response = client.chat.completions.create(
            model="solar-mini",
            messages=[
                {"role": "system", "content": SYSTEM_INSTRUCTION},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}, # JSON 모드 강제
            temperature=0.2,
            stream=False 
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Initial API call failed: {e}. Retrying...")
        # 재시도 로직
        try:
            retry_prompt = prompt + "\n\n주의: 반드시 유효한 JSON 형식으로만 응답해야 합니다."
            response = client.chat.completions.create(
                model="solar-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_INSTRUCTION},
                    {"role": "user", "content": retry_prompt}
                ],
                response_format={"type": "json_object"}
            )
            return response.choices[0].message.content
        except Exception as retry_e:
             print(f"Retry failed: {retry_e}")
             raise retry_e

# 5. 유저 프롬프트 생성 함수
def build_user_prompt(from_iso, to_iso, logs_chunk):
    return f"""
분석 대상 환경 정보:
- env: prod
- service: snorose-backend
- region: ap-northeast-2
- 기간: {from_iso} ~ {to_iso}
- 알려진 변경: 없음

다음 로그를 분석해주세요:

---LOGS START---
{logs_chunk}
---LOGS END---
""".strip()

# 6. 민감 정보 마스킹 함수
SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|token|secret)\s*[:=]\s*([A-Za-z0-9\-\._]{8,})'),
    re.compile(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}'),       # IP 주소
    re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')  # 이메일
]

def mask_secrets(text: str) -> str:
    for pat in SECRET_PATTERNS:
        text = pat.sub('[REDACTED]', text)
    return text

# === Upstage 설정 끝 ===

def lambda_handler(event, context):
    try:
        # 7. 안정적인 KST 시간 계산
        KST = timezone(timedelta(hours=9))
        now_utc = datetime.datetime.now(timezone.utc)
        now_kst = now_utc.astimezone(KST)

        # EventBridge 스케줄 시간에 따라 분석 시작 시간 결정
        if now_kst.hour >= 23:
            start_kst = now_kst.replace(hour=16, minute=0, second=0, microsecond=0)
        elif now_kst.hour >= 16:
            start_kst = now_kst.replace(hour=8, minute=0, second=0, microsecond=0)
        elif now_kst.hour >= 8:
             start_kst = (now_kst - timedelta(days=1)).replace(hour=23, minute=0, second=0, microsecond=0)
        else: # 수동 실행 또는 새벽 시간대
            print("Manual trigger or off-schedule. Defaulting to last 15 minutes.")
            start_kst = now_kst - timedelta(minutes=15)

        start_utc = start_kst.astimezone(timezone.utc)
        
        start_time_ns = int(start_utc.timestamp() * 1e9)
        end_time_ns = int(now_utc.timestamp() * 1e9)

        all_error_logs = [
            "[2025-02-01 14:05:01] ERROR o.a.c.c.C.[Tomcat].[localhost] - Servlet.service() for servlet [dispatcherServlet] threw exception",
            "[2025-02-01 14:05:01] ERROR o.s.b.w.s.ErrorPageFilter - Forwarding to error page from request [/api/users/me] due to exception",
            "[2025-02-01 14:05:01] ERROR o.h.e.jdbc.spi.SqlExceptionHelper - SQL Error: 0, SQLState: 08001",
            "[2025-02-01 14:05:01] ERROR o.h.e.jdbc.spi.SqlExceptionHelper - Communications link failure",
            "[2025-02-01 14:05:01] ERROR c.z.h.HikariPool - HikariPool-1 - Connection is not available, request timed out after 30000ms",
            "[2025-02-01 14:05:05] FATAL c.z.h.HikariPool - HikariPool-1 - Pool is exhausted, shutting down",
            "[2025-02-01 14:05:06] ERROR o.s.b.SpringApplication - Application run failed",
            "[2025-02-01 14:05:06] ERROR o.s.b.d.LoggingFailureAnalysisReporter - APPLICATION FAILED TO START",
            "[2025-02-01 14:05:06] ERROR o.s.b.d.LoggingFailureAnalysisReporter - Description: Failed to initialize database connection",
            "[2025-02-01 14:05:06] ERROR o.s.b.d.LoggingFailureAnalysisReporter - Action: Check database availability and credentials"
        ]
        
        include_keywords = "ERROR|failed|500|Exception"
        exclude_keywords = "IllegalArgumentException|AccessDeniedException" 

        # for job_label in LOKI_JOB_LABELS_TO_ANALYZE:
        #     loki_query = f'{{job="{job_label}"}} |~ "{include_keywords}" !~ "{exclude_keywords}"'
        #     url = f"{LOKI_URL}/loki/api/v1/query_range"
        #     params = {'query': loki_query, 'start': str(start_time_ns), 'end': str(end_time_ns), 'direction': 'forward', 'limit': 5000}
        #     print(f"Querying Loki with adjusted LogQL: {loki_query}")
        #     try:
        #         response = requests.get(url, params=params, timeout=60)
        #         response.raise_for_status()
        #         loki_data = response.json()
        #         if loki_data['data']['resultType'] == 'streams':
        #             for stream in loki_data['data']['result']:
        #                 for entry in stream['values']:
        #                     all_error_logs.append(f"[{datetime.datetime.fromtimestamp(int(entry[0]) / 1e9).strftime('%Y-%m-%d %H:%M:%S')}] {entry[1]}")
        #     except requests.exceptions.RequestException as e:
        #         print(f"Error querying Loki for {job_label}: {e}")
        #         continue

        kst_start_time = start_utc.astimezone(KST)
        kst_current_time = now_utc.astimezone(KST)

        if not all_error_logs:
            print("No critical logs found. System is stable.")
            alert_subject = f"✅ {kst_start_time.strftime('%H:%M')}~{kst_current_time.strftime('%H:%M')} 시스템 안정"
            alert_message = "모니터링 주기 동안 심각한 에러 로그가 발견되지 않았습니다."
            sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=alert_subject, Message=alert_message)
            return {'statusCode': 200, 'body': json.dumps('No critical logs to process.')}

        unique_logs = sorted(list(set(all_error_logs)))
        
        # 8. LLM 전송 전 민감 정보 마스킹
        logs_to_summarize = mask_secrets("\n".join(unique_logs))

        from_iso = start_utc.isoformat().replace('+00:00', 'Z')
        to_iso = now_utc.isoformat().replace('+00:00', 'Z')
        prompt = build_user_prompt(from_iso, to_iso, logs_to_summarize[:15000])
        
        print(f"Sending {len(unique_logs)} unique abnormal logs to Upstage API.")
        
        summary_text = "요약 생성에 실패했습니다."
        try:
            # Upstage 호출
            upstage_json_str = call_upstage_json(prompt)
            result = json.loads(upstage_json_str)
            summary_text = result.get("summary_md", "Upstage가 로그를 분석했지만 요약할 만한 중요 사건을 발견하지 못했습니다.")
            
        except (json.JSONDecodeError, Exception) as e:
            print(f"Failed to get structured JSON response: {e}. Falling back to simple summary.")
            fallback_prompt = "다음 로그들을 보고, 현재 발생한 문제 상황을 2~3문장의 자연스러운 한국어로 간단명료하게 요약해줘.\n\n" + logs_to_summarize[:12000]
            
            # Fallback 호출 (일반 텍스트)
            try:
                fallback_response = client.chat.completions.create(
                    model="solar-mini",
                    messages=[
                        {"role": "system", "content": "You are a helpful SRE assistant."},
                        {"role": "user", "content": fallback_prompt}
                    ]
                )
                summary_text = fallback_response.choices[0].message.content
            except Exception as fallback_e:
                summary_text = f"분석 및 폴백 모두 실패: {fallback_e}"

        alert_subject = f"🚨 {kst_start_time.strftime('%H:%M')}~{kst_current_time.strftime('%H:%M')} 비정상 로그 발생"
        
        sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=alert_subject, Message=summary_text)
        print("Abnormal log summary alert published to SNS topic.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise e

    return {'statusCode': 200, 'body': json.dumps('Log processing complete.')}
