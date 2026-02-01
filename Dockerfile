# 파이썬 버전 3.12 명시
FROM public.ecr.aws/lambda/python:3.12

# 파이썬 의존성 설치
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# 캐시 없이 설치하여 이미지 크기 최적화
RUN pip install --no-cache-dir -r requirements.txt

# Lambda 함수 코드 복사
COPY lambda_function.py ${LAMBDA_TASK_ROOT}

# Lambda 핸들러 설정
CMD [ "lambda_function.lambda_handler" ]