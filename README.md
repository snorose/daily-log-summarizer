## Daily Log Summarizer

daily-log-summarizer는 AWS 인프라와 Upstage Solar LLM을 결합하여 실시간으로 서버 로그를 분석하고, 핵심 장애 상황을 요약하여 전달하는 지능형 SRE 어시스턴트입니다.

<br>

## Architecture

![architecture](/images/architecture.png)<br>
1. EC2 인스턴스의 Spring Boot 앱 로그를 Promtail이 수집하여 Grafana Loki로 전송합니다
2. Amazon EventBridge가 정해진 스케줄(KST 기준)에 맞춰 분석 Lambda를 트리거합니다.
3. AWS Lambda가 Loki에서 비정상 로그를 쿼리하고, Upstage Solar API를 호출하여 로그의 문맥을 분석 및 요약합니다.
4. 요약된 리포트는 Amazon SNS를 통해 전달되며, 최종적으로 Discord 채널로 알림이 전송됩니다.

<br>

## Key Features

- Intelligent Summarization: solar-mini 모델을 사용하여 복잡한 스택 트레이스에서 장애의 근본 원인을 자연어로 요약합니다.
- Structured Output: JSON 모드를 활용하여 사건 발생 시간, 영향도, Confidence 등을 구조화된 데이터로 관리합니다.
- Privacy First: LLM 전송 전 민감 정보를 자동으로 [REDACTED] 처리하여 보안 가이드라인을 준수합니다.
- Fully Automated: Docker 기반의 ECR 배포와 GitHub Actions CI/CD를 통해 인프라 관리를 자동화했습니다.

<br>

## Tech Stack

- Language: Python 3.12
- AI Engine: Upstage Solar LLM (solar-mini)
- Cloud: AWS (Lambda, EventBridge, SNS, SSM, ECR)
- Monitoring: Grafana Loki, Promtail
- CI/CD: GitHub Actions, Docker