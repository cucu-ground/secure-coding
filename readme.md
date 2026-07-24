# 시큐어 코딩 과제

## 프로젝트 소개

간단한 중고거래 웹 서비스입니다. 회원가입, 로그인, 프로필 관리, 상품 등록/조회/검색/수정/삭제, 신고, 실시간 전체 채팅, 1대1 메시지, 송금, 관리자 관리 기능을 제공합니다.

기존 기능에 보안 요구사항을 반영하여 안전하게 동작하도록 수정했습니다.

## 실행 환경 준비

Miniconda 또는 Anaconda가 없다면 아래 주소에서 설치할 수 있습니다.

https://www.anaconda.com/docs/getting-started/miniconda/install

```bash
git clone https://github.com/ugonfor/secure-coding
cd secure-coding
conda env create -f enviroments.yaml
conda activate secure_coding
```

## 실행 방법

```bash
python app.py
```

실행 후 브라우저에서 아래 주소로 접속합니다.

```text
http://127.0.0.1:5000
```

외부 기기에서 테스트해야 하는 경우에는 ngrok 같은 포트 포워딩 도구를 사용할 수 있습니다.

```bash
sudo snap install ngrok
ngrok http 5000
```

## 구현한 보안 항목

- 회원가입, 로그인, 프로필, 상품, 신고, 채팅 입력값에 대한 서버측 검증
- 모든 POST 폼에 CSRF 토큰 검증 적용
- 비밀번호 평문 저장 제거 및 해시 저장 적용
- 세션 만료 시간 설정
- 세션 쿠키에 HttpOnly, SameSite, 운영 환경 Secure 설정 적용
- 로그인 실패 횟수 제한
- 상품 수정/삭제 시 판매자 본인 여부 확인
- 신고 중복 방지 및 1시간 신고 횟수 제한
- 신고 및 주요 활동 감사 로그 저장
- Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy 보안 헤더 적용
- 실시간 채팅 로그인 검증, 메시지 검증, XSS 이스케이프, 전송 속도 제한
- 모든 SQL 쿼리에 파라미터 바인딩을 사용하여 SQL Injection 방어

## 구현한 주요 기능

- 회원가입 및 로그인
- 사용자 프로필 조회 및 소개글 수정
- 현재 비밀번호 확인 후 비밀번호 변경
- 상품 등록, 목록 조회, 상세 조회, 검색
- 상품명, 설명, 가격, 사진 URL 관리
- 본인이 등록한 상품 수정 및 삭제
- 전체 사용자 실시간 채팅
- 사용자 간 1대1 메시지
- 사용자 간 송금 및 송금 내역 확인
- 악성 사용자 또는 상품 신고
- 신고 누적 시 상품 자동 차단 또는 사용자 휴면 처리
- 관리자 페이지에서 사용자 휴면 처리/해제, 상품 차단/해제, 신고 내역 확인

첫 번째로 가입한 사용자는 자동으로 관리자 권한을 갖습니다.

## 운영 시 주의사항

운영 환경에서는 반드시 강한 `SECRET_KEY`를 환경 변수로 설정해야 합니다.

```bash
export SECRET_KEY="충분히_긴_랜덤_문자열"
```

운영 환경에서는 HTTPS를 적용해야 쿠키의 Secure 설정과 WSS 기반 웹소켓 통신을 안전하게 사용할 수 있습니다.
