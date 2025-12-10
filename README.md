네트워크프로그래밍 기말과제
2025. 11.

1. 개요
소켓 API와 파이썬을 이용하여 TFTP 클라이언트를 작성한다. 작성된 클라이언트는 FTP서버(tftpd-hpa)와 프로토콜에 따라 동작하여야 한다.

2. 클라이언트 기능

- 클라이언트는 파일을 다운로드(get)하거나 업로드(put)한다.
- 전송모드는 ‘octet’ 모드만 지원한다
- 호스트 주소는 도메인네임(예: genie.pcu.ac.kr) 이나 IP 주소(예 203.250.133.88)로 지정한다 
- 포트 설정 기능을 가진다: (서버포트가 69번이 아닐 경우에 사용하기 위함)
- RRQ, WRQ에 서버가 응답이 없을 경우에 대한 처리를 해야 한다.
- ‘File not found’ 와  ‘File arleady exists’ 오류를 처리해야 한다. 


3. 클라이언트 실행 
  $ mytftp host [-p port] [get|put] filename 
  예: 
     $ mytftp 203.250.133.88 get tftp.conf
     $ mytftp 203.250.133.88 put tftp.txt
     $ mytftp genie.pcu.ac.kr –p 9988 put tftp.txt

4. 과제 제출
- LMS 업로드
   - 보고서 (보고서 표지에 Github URL 명시) 
- Github 업로드 
    - source file 
    - README 
- 기일 엄수 
    - 보고서 업로드는 기말고사 기간 주말까지
    - 프로그램 데모는 마지막 수업시간에 실시
