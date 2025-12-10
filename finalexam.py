#!/usr/bin/python3

#리눅스에서 실행 파일처럼 쓸 수 있게 하는 shebang.
import socket
import argparse
from struct import pack
import sys
import os

# 기본 설정
DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'octet' #octet 모드만 사용
TIME_OUT = 1.0          # 소켓 타임아웃 시간(초)
MAX_TRY = 5             # 재전송 최대 횟수

# Opcode 정의
OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}

# 에러 코드 정의(서버가 ERROR 패킷으로 보내는 error code를 사람이 읽을 수 있는 문자열로 바꿔주는 용도)
ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.", #서버에 해당 파일이 없는 경우
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.", #서버에 동일 이름 파일이 이미 존재하는 경우
    7: "No such user."
}

# 전역 소켓 / 서버 주소는 main에서 설정
sock = None
server_address = None


def build_request(opcode, filename, mode):#RRQ/WRQ 요청 패킷 만들기
    fmt = f'>h{len(filename)}sB{len(mode)}sB'
    return pack(fmt,
                opcode,
                filename.encode('utf-8'), 0,
                mode.encode('utf-8'), 0)


def send_ack(block_number, peer_addr):#ACK 전송 함수
    ack_packet = pack('>hh', OPCODE['ACK'], block_number)
    sock.sendto(ack_packet, peer_addr)


def handle_error_packet(data):#ERROR 패킷 처리
    if len(data) < 4:
        print("Error: malformed ERROR packet.")
        return
    code = int.from_bytes(data[2:4], 'big')
    msg = ERROR_CODE.get(code, "Unknown error")
    print(f"[TFTP ERROR] Code {code}: {msg}")


def tftp_get(filename, mode):#파일 다운로드 함수
    # RRQ 패킷 생성
    request = build_request(OPCODE['RRQ'], filename, mode)
    # RRQ 전송 및 첫 응답 대기 (RRQ에 대한 타임아웃 처리)
    attempts = 0
    while True:
        sock.sendto(request, server_address) #RRQ 요청 전송
        try:
            data, peer = sock.recvfrom(4 + BLOCK_SIZE)
            opcode = int.from_bytes(data[:2], 'big')
            break 
        except socket.timeout:
            attempts += 1 # MAX_TRY 만큼 재시도 후에도 응답이 없으면 포기
            if attempts >= MAX_TRY:
                print("RRQ: no response from server. Aborting.")
                return
            print("RRQ timeout, retrying...")

    # ERROR 패킷 처리(에러/데이터 유무 확인)
    if opcode == OPCODE['ERROR']:
        handle_error_packet(data)
        return
		# 4. 첫 응답이 DATA가 아니면 비정상 패킷으로 간주하고 종료
    if opcode != OPCODE['DATA']:
        print("Unexpected packet instead of DATA. Aborting.")
        return

    expected_block = 1 #첫 DATA 블록 처리 준비
    block_number = int.from_bytes(data[2:4], 'big')
    data_block = data[4:]

    try:
        # 같은 이름으로 파일 생성(기존 파일 덮어씀)
        with open(filename, 'wb') as f:
            while True:
                if block_number == expected_block:
                    # 데이터 쓰기 & ACK 전송
                    f.write(data_block)
                    send_ack(block_number, peer)

                    # 마지막 블록이면 종료 (꼬임방지)
                    if len(data_block) < BLOCK_SIZE:
                        print("File download completed.")
                        break

                    expected_block += 1
                else:
                    # 기대하는 블록이 아니면 마지막 정상 블록 ACK 재전송
                    send_ack(expected_block - 1, peer)

                # 다음 DATA 패킷 수신
                attempts = 0
                while True:
                    try:
                        data, peer = sock.recvfrom(4 + BLOCK_SIZE)
                        opcode = int.from_bytes(data[:2], 'big')
                        break
                    except socket.timeout:
                        attempts += 1
                        # 지정된 재시도 횟수를 초과하면 전송 중단
                        if attempts >= MAX_TRY:
                            print("Data receive timeout. Aborting.")
                            return
                        # 마지막 정상 블록 ACK 재전송
                        send_ack(expected_block - 1, peer)

                if opcode == OPCODE['ERROR']:
                    handle_error_packet(data)
                    return
                    # DATA가 아닌 예기치 못한 패킷 수신 시 중단
                if opcode != OPCODE['DATA']:
                    print("Unexpected packet during transfer. Aborting.")
                    return

                block_number = int.from_bytes(data[2:4], 'big')
                data_block = data[4:]

    except OSError as e:
        print(f"File write error: {e}")
       

def tftp_put(filename, mode):#파일 업로드 함수
    if not os.path.exists(filename): #파일 존재 유무 확인
        print(f"Local file '{filename}' not found. Aborting.")
        return

    request = build_request(OPCODE['WRQ'], filename, mode)

    # WRQ 전송 및 첫 응답 대기 (WRQ에 대한 타임아웃 처리)
    attempts = 0
    while True:
        sock.sendto(request, server_address)
        try:
            resp, peer = sock.recvfrom(4 + BLOCK_SIZE)
            opcode = int.from_bytes(resp[:2], 'big')
            break
        except socket.timeout:
            attempts += 1
            if attempts >= MAX_TRY:
                print("WRQ: no response from server. Aborting.")
                return
            print("WRQ timeout, retrying...")
		#첫 응답이 ERROR이면 에러 메시지 출력 후 종료
    if opcode == OPCODE['ERROR']:
        handle_error_packet(resp)
        return

    if opcode != OPCODE['ACK']:
        print("Unexpected packet instead of ACK(0). Aborting.")
        return

    ack_block = int.from_bytes(resp[2:4], 'big')
    if ack_block != 0:
        print("Expected ACK for block 0, got different block. Aborting.")
        return

    # 이제 peer(새 포트)와 데이터 전송 시작
    try:
        with open(filename, 'rb') as f: #읽기 모드로 open
            block_number = 0
            while True:
                data_block = f.read(BLOCK_SIZE)
                block_number += 1

                data_packet = pack('>hh', OPCODE['DATA'], block_number) + data_block

                attempts = 0
                while True:
                    sock.sendto(data_packet, peer)
                    try:
                        resp, peer = sock.recvfrom(4 + BLOCK_SIZE)
                        opcode = int.from_bytes(resp[:2], 'big')
                    except socket.timeout:
		                    # 타임아웃 발생 시 동일 블록 재전송
                        attempts += 1
                        if attempts >= MAX_TRY:
                            print("DATA send timeout. Aborting.")
                            return
                        print(f"Timeout on block {block_number}, resending...")
                        continue
										 #ERROR 패킷을 수신한 경우
                    if opcode == OPCODE['ERROR']:
                        handle_error_packet(resp)
                        return
                    if opcode != OPCODE['ACK']:
                        print("Unexpected packet during upload. Aborting.")
                        return

                    ack_block = int.from_bytes(resp[2:4], 'big')
                    if ack_block == block_number:
                        # 정상 ACK → 다음 블록으로
                        break
                    else:
                        print(f"Unexpected ACK block {ack_block}, expected {block_number}. Ignoring...")
                        attempts += 1
                        if attempts >= MAX_TRY:
                            print("Too many wrong ACKs. Aborting.")
                            return

                # 마지막 블록이면 종료
                if len(data_block) < BLOCK_SIZE:
                    print("File upload completed.")
                    break

    except OSError as e:
        print(f"File read error: {e}")
        return


def main():
    global sock, server_address
    parser = argparse.ArgumentParser(description='TFTP client program')
    parser.add_argument("host", help="Server IP address or hostname", type=str)
    parser.add_argument("-p", "--port", dest="port", type=int, # 69포트 외에 사용 가능
                        default=DEFAULT_PORT,
                        help="Server port (default: 69)")
    parser.add_argument("operation", help="get or put a file",# get 또는 put 중 하나 선택
                        type=str, choices=["get", "put"])
    parser.add_argument("filename", help="name of file to transfer", type=str)
    args = parser.parse_args()

		# 서버 주소 (IP/도메인, 포트) 설정
    server_ip = args.host
    server_port = args.port
    server_address = (server_ip, server_port)

    # UDP 소켓 생성
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIME_OUT)

    mode = DEFAULT_TRANSFER_MODE
    op = args.operation
    filename = args.filename

    try: 
        if op == "get":
            tftp_get(filename, mode)
        elif op == "put":
            tftp_put(filename, mode)
    finally:
        sock.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
