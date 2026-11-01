# -*- coding: utf-8 -*-
"""test_cert_gate.py —— 证书闸门测试。

写入 hosts 前必须确认选中的 IP 对所有目标域名都持有合法证书，
否则浏览器会直接报证书错误，比不配还糟。

这个测试需要一个真实可用的 CF IP，所以标记为「联网测试」：
    python test_cert_gate.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cf_hunt

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")
        if detail:
            print(f"         {detail}")


def test_selfsigned_rejected():
    """反向验证：自签证书必须被判 bad。

    没有这一条，闸门可能只是「看起来在工作」。
    """
    print("\n--- 场景6：自签证书必须被判 bad（反向验证） ---")
    import datetime
    import socket
    import ssl
    import tempfile
    import threading

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("  [SKIP] 未安装 cryptography，跳过反向验证")
        return

    d = tempfile.mkdtemp()
    key_path = os.path.join(d, "key.pem")
    crt_path = os.path.join(d, "crt.pem")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "evil.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(crt_path, key_path)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(5)
    srv.settimeout(0.5)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                srv_ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        state, msg = cf_hunt.cert_ok("127.0.0.1", "open-design.ai",
                                     timeout=5, tries=1, port=port)
        check(f"自签证书 state = {state}（应为 bad）", state == "bad", msg)
    finally:
        stop.set()
        try:
            srv.close()
        except OSError:
            pass


def main():
    print("=" * 66)
    print(" 证书闸门测试")
    print("=" * 66)

    # ---------------------------------------------------------- 上下文正确性
    print("\n--- 场景1：严格校验上下文必须加载系统根证书 ---")
    ctx = cf_hunt._strict_ctx()
    n_roots = len(ctx.get_ca_certs())
    check(f"根证书数 = {n_roots}（>0 才可能校验通过）", n_roots > 0,
          "直接用 SSLContext(PROTOCOL_TLS_CLIENT) 会是 0 个，导致任何证书都报"
          " unable to get local issuer certificate")
    check("check_hostname 已开启", ctx.check_hostname is True)
    check("verify_mode 是 CERT_REQUIRED",
          ctx.verify_mode.name == "CERT_REQUIRED" if hasattr(ctx.verify_mode, "name")
          else ctx.verify_mode == 2)

    # ---------------------------------------------------------- 域名清单
    print("\n--- 场景2：默认域名必须包含客户端 API 域名 ---")
    check("open-design.ai 在默认域名里", "open-design.ai" in cf_hunt.DOMAINS)
    check("www.open-design.ai 在默认域名里",
          "www.open-design.ai" in cf_hunt.DOMAINS)
    check("amr-link.open-design.ai 在默认域名里（客户端 API）",
          "amr-link.open-design.ai" in cf_hunt.DOMAINS,
          f"当前 DOMAINS = {cf_hunt.DOMAINS}")

    # ---------------------------------------------------------- 三态判定
    print("\n--- 场景3：连不上必须报 error，不能报成证书无效 ---")
    state, msg = cf_hunt.cert_ok("127.0.0.1", "open-design.ai", timeout=2.0,
                                 tries=1)
    check(f"本地地址 state = {state}（应为 error）", state == "error",
          f"实际 {state}: {msg}")

    print("\n--- 场景4：连不上的 IP 不能被 cert_gate 放行 ---")
    passing, details = cf_hunt.verify_cert_all(["127.0.0.1"],
                                               ["open-design.ai"],
                                               timeout=2.0)
    check("127.0.0.1 未通过", passing == [], f"实际 {passing}")

    # ---------------------------------------------------------- 真实 IP
    print("\n--- 场景5：真实 CF IP 应通过全部三个域名 ---")
    real_ip = "104.18.57.1"
    passing, details = cf_hunt.verify_cert_all([real_ip], cf_hunt.DOMAINS)
    check(f"{real_ip} 通过证书校验", passing == [real_ip],
          f"实际 {passing}; 详情 {details}")
    for d in details:
        print(f"    {d}")

    # ---------------------------------------------------------- 反向验证
    test_selfsigned_rejected()

    # ---------------------------------------------------------- 汇总
    print("\n" + "=" * 66)
    print(f" 通过 {PASS} 项，失败 {FAIL} 项")
    print("=" * 66)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
