import pefile
import datetime
import hashlib
import math
import argparse
import sys
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms

SUBSYSTEMS = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI (콘솔)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI 애플리케이션",
    11: "EFI 부트 서비스 드라이버",
    12: "EFI 런타임 드라이버",
    13: "EFI ROM",
    14: "Xbox"
}

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def format_compile_time(timestamp: int, tz_hours: int = 9) -> str:
    utc_time = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
    kst = datetime.timezone(datetime.timedelta(hours=tz_hours))
    local_time = utc_time.astimezone(kst)
    return local_time.strftime('%Y-%m-%d %H:%M:%S')

def print_hashes(data: bytes) -> None:
    hashes = {
        'MD5': hashlib.md5(data).hexdigest(),
        'SHA1': hashlib.sha1(data).hexdigest(),
        'SHA256': hashlib.sha256(data).hexdigest()
    }
    print("[+] 파일 해시값:")
    for name, value in hashes.items():
        print(f"    - {name}: {value}")

def get_architecture(pe: pefile.PE) -> str:
    magic = pe.OPTIONAL_HEADER.Magic
    if magic == 0x10B:
        return "32비트 (PE32)"
    if magic == 0x20B:
        return "64비트 (PE32+)"
    return f"알 수 없음 (Magic: 0x{magic:X})"

def get_file_type(pe: pefile.PE) -> str:
    characteristics = pe.FILE_HEADER.Characteristics
    return "DLL (동적 링크 라이브러리)" if characteristics & 0x2000 else "EXE (실행 파일)"

def get_subsystem(pe: pefile.PE) -> str:
    val = pe.OPTIONAL_HEADER.Subsystem
    return SUBSYSTEMS.get(val, f"알 수 없음 ({val})")

def print_sections(pe: pefile.PE, image_base: int) -> None:
    print("[+] 섹션 목록:")
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode(errors='ignore')
        vaddr = section.VirtualAddress + image_base
        vsize = section.Misc_VirtualSize
        print(f"    - {name:8} | VA: 0x{vaddr:08X} | Size: {vsize} bytes")

def find_section_for_oep(pe: pefile.PE, entry_point_rva: int) -> Optional[str]:
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + section.Misc_VirtualSize
        if start <= entry_point_rva < end:
            return section.Name.rstrip(b'\x00').decode(errors='ignore')
    return None

def print_debug_info(pe: pefile.PE) -> None:
    print("[+] 디버깅 정보:")
    pdb_found = False
    for dbg in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', []):
        if dbg.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            data = pe.__data__[dbg.struct.PointerToRawData: dbg.struct.PointerToRawData + dbg.struct.SizeOfData]
            if data[:4] == b'RSDS':
                pdb_path = data[24:].split(b'\x00', 1)[0].decode(errors='ignore')
                print(f"    - PDB 경로: {pdb_path}")
                pdb_found = True
    if not pdb_found:
        print("    - PDB 디버깅 정보가 없습니다.")

def parse_and_print_certificate(cert_der_bytes):
    try:
        cert_obj = x509.load_der_x509_certificate(cert_der_bytes, default_backend())
        print(f"    - 인증서 주체: {cert_obj.subject.rfc4514_string()}")
        print(f"      인증서 발급자: {cert_obj.issuer.rfc4514_string()}")
        print(f"      유효 기간: {cert_obj.not_valid_before} ~ {cert_obj.not_valid_after}")
        print(f"      시리얼 번호: {cert_obj.serial_number}")
    except Exception as e:
        print(f"      인증서 파싱 실패: {e}")

def print_certificate_info(pe: pefile.PE, file_path: str) -> None:
    print("[+] 임베디드 서명 (Embedded Signature) 정보:")
    cert_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    if cert_entry.VirtualAddress == 0 or cert_entry.Size == 0:
        print("    - 디지털 서명이 없습니다.")
    else:
        try:
            with open(file_path, 'rb') as f:
                f.seek(cert_entry.VirtualAddress)
                signature_data = f.read(cert_entry.Size)

            # 윈도우 인증서 헤더(8바이트) 제거 후 PKCS#7 파싱
            pkcs7_data = signature_data[8:]

            content_info = cms.ContentInfo.load(pkcs7_data)
            if content_info['content_type'].native != 'signed_data':
                print("    - PKCS#7 SignedData 구조가 아닙니다.")
                return

            signed_data = content_info['content']

            certs = signed_data['certificates']
            if certs is None or len(certs) == 0:
                print("    - 인증서가 없습니다.")
                return

            print(f"    - 포함된 인증서 수: {len(certs)}")

            for cert in certs:
                if isinstance(cert, cms.CertificateChoices):
                    cert_der = cert.chosen.dump()
                    parse_and_print_certificate(cert_der)
                    print("    " + "-"*40)

            # 서명자 정보 및 카운터서명 출력
            signer_infos = signed_data['signer_infos']
            for i, signer_info in enumerate(signer_infos, 1):
                print(f"    - 서명자 {i} 정보:")
                sid = signer_info['sid']
                if sid.name == 'issuer_and_serial_number':
                    issuer = sid.chosen['issuer'].human_friendly
                    serial = sid.chosen['serial_number'].native
                    print(f"      - 발급자: {issuer}")
                    print(f"      - 시리얼 번호: {serial}")
                else:
                    print(f"      - 서명자 ID 타입: {sid.name}")

                unsigned_attrs = signer_info['unsigned_attrs']
                if unsigned_attrs is not None:
                    for attr in unsigned_attrs:
                        if attr['type'].native == 'counter_signature':
                            print("      - 카운터 서명 정보 (Catalog Signature 등):")
                            for cs in attr['values']:
                                cs_sid = cs['sid']
                                if cs_sid.name == 'issuer_and_serial_number':
                                    cs_issuer = cs_sid.chosen['issuer'].human_friendly
                                    cs_serial = cs_sid.chosen['serial_number'].native
                                    print(f"        * 발급자: {cs_issuer}")
                                    print(f"        * 시리얼 번호: {cs_serial}")

        except Exception as e:
            print(f"    - 인증서 정보 파싱 중 오류 발생: {e}")

def print_imports(pe: pefile.PE) -> None:
    print("[+] Import 함수 목록:")
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("    - Import 데이터가 없습니다.")
        return

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors='ignore')
        print(f"    - {dll_name}:")
        if not entry.imports:
            print("        (함수 없음)")
            continue
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode(errors='ignore')
            else:
                func_name = f"Ordinal_{imp.ordinal}"
            print(f"        * {func_name}")

def analyze_pe(file_path: str, show_imports: bool = False) -> None:
    try:
        print(f"[+] 분석 대상 파일: {file_path}\n")

        with open(file_path, 'rb') as f:
            data = f.read()

        entropy = calculate_entropy(data)
        print(f"[+] 전체 파일 엔트로피: {entropy:.4f} bits/byte\n")
        print(f"[+] 파일 크기: {len(data)} 바이트")

        print_hashes(data)

        pe = pefile.PE(data=data)

        compile_time_str = format_compile_time(pe.FILE_HEADER.TimeDateStamp)
        print(f"\n[+] 컴파일 시간: {compile_time_str} (KST)")

        file_type = get_file_type(pe)
        print(f"[+] 파일 타입: {file_type}")

        arch = get_architecture(pe)
        print(f"[+] 아키텍처: {arch}")

        subsystem = get_subsystem(pe)
        print(f"[+] 서브시스템: {subsystem} (값: {pe.OPTIONAL_HEADER.Subsystem})")

        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        oep = image_base + entry_point_rva
        print(f"[+] OEP (Original Entry Point): 0x{oep:08X}")

        print_sections(pe, image_base)

        section_name = find_section_for_oep(pe, entry_point_rva)
        if section_name:
            print(f"[+] OEP가 포함된 섹션: {section_name}")
        else:
            print("[+] OEP 섹션을 찾지 못했습니다.")

        print_debug_info(pe)

        print_certificate_info(pe, file_path)

        if show_imports:
            print_imports(pe)

    except Exception as e:
        print(f"[!] 분석 중 오류 발생: {e}")

def main():
    parser = argparse.ArgumentParser(description="PE 파일 상세 분석기 (임베디드 서명 + 카탈로그 서명 포함)")
    parser.add_argument('file', help="분석할 PE 파일 경로")
    parser.add_argument('--imports', action='store_true', help="Import 함수 목록 출력")
    args = parser.parse_args()

    analyze_pe(args.file, args.imports)

if __name__ == '__main__':
    main()
