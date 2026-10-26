#!/bin/sh
# Hyperdown 每日自动签到脚本
#
# 用法:
#   ./hyperdown-checkin.sh                # 执行签到
#   ./hyperdown-checkin.sh --status       # 查看当前账号签到状态
#   ./hyperdown-checkin.sh --selftest     # 校验内置加密实现
#   ./hyperdown-checkin.sh --state FILE   # 指定 token 状态文件
#
# 依赖: python3 (3.8+)，无第三方库。
#
# 首次运行会用脚本内置的 token 创建状态文件（默认 ~/.hyperdown_checkin.json），
# 之后 access token 过期会自动用 refresh token 续期并把新 token 写回状态文件。
# 注意: 服务端每次 refresh 都会轮换 refresh token，因此状态文件不要丢失；
#       也请不要在脚本之外（例如客户端里）同时刷新同一账号，二者会互相失效。

set -u

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    if command -v python >/dev/null 2>&1; then
        PYTHON=python
    else
        echo "错误: 需要 python3 (未找到 python3/python)" >&2
        exit 127
    fi
fi

exec "$PYTHON" - "$@" <<'PYEOF'
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------- 常量
API_BASE = "https://hyperdown.net/api/v1"
SERVER_PUB_HEX = "dd85f63f107a32ce3def4835fe56c27865a1557fedad19adbd72ff81ea2e1025"
INFO_PREFIX = b"hyperdown-secure-api:v1:"
CHECKIN_PATH = "/api/v1/me/checkins"
STATE_DEFAULT = os.path.expanduser("~/.hyperdown_checkin.json")

# 仓库内不保存任何 token：优先读状态文件，其次读环境变量。
DEFAULT_ACCESS = ""
DEFAULT_REFRESH = ""

P25519 = 2 ** 255 - 19


# ---------------------------------------------------------------- 编解码
def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def jwt_exp(token):
    """返回 JWT 的 exp (unix 秒)，解析失败返回 0。"""
    try:
        payload = token.split(".")[1]
        data = json.loads(b64u_dec(payload).decode("utf-8"))
        return int(data.get("exp") or 0)
    except Exception:
        return 0


# ---------------------------------------------------------------- X25519
def _cswap(swap, a, b):
    dummy = swap * (a - b)
    return a - dummy, b + dummy


def x25519(scalar, u):
    k = bytearray(scalar[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(bytes(k), "little")
    x1 = int.from_bytes(u[:32], "little") & ((1 << 255) - 1)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k_int >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt
        a = (x2 + z2) % P25519
        aa = a * a % P25519
        b = (x2 - z2) % P25519
        bb = b * b % P25519
        e = (aa - bb) % P25519
        c = (x3 + z3) % P25519
        d = (x3 - z3) % P25519
        da = d * a % P25519
        cb = c * b % P25519
        x3 = (da + cb) ** 2 % P25519
        z3 = x1 * (da - cb) ** 2 % P25519
        x2 = aa * bb % P25519
        z2 = e * (aa + 121665 * e) % P25519
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, P25519 - 2, P25519) % P25519).to_bytes(32, "little")


X25519_BASE = (9).to_bytes(32, "little")


# ---------------------------------------------------------------- ChaCha20
M32 = 0xFFFFFFFF


def _rotl(v, c):
    return ((v << c) | (v >> (32 - c))) & M32


def _chacha_rounds(state, rounds=20):
    x = list(state)
    for _ in range(rounds // 2):
        x[0] = (x[0] + x[4]) & M32; x[12] ^= x[0]; x[12] = _rotl(x[12], 16)
        x[8] = (x[8] + x[12]) & M32; x[4] ^= x[8]; x[4] = _rotl(x[4], 12)
        x[0] = (x[0] + x[4]) & M32; x[12] ^= x[0]; x[12] = _rotl(x[12], 8)
        x[8] = (x[8] + x[12]) & M32; x[4] ^= x[8]; x[4] = _rotl(x[4], 7)

        x[1] = (x[1] + x[5]) & M32; x[13] ^= x[1]; x[13] = _rotl(x[13], 16)
        x[9] = (x[9] + x[13]) & M32; x[5] ^= x[9]; x[5] = _rotl(x[5], 12)
        x[1] = (x[1] + x[5]) & M32; x[13] ^= x[1]; x[13] = _rotl(x[13], 8)
        x[9] = (x[9] + x[13]) & M32; x[5] ^= x[9]; x[5] = _rotl(x[5], 7)

        x[2] = (x[2] + x[6]) & M32; x[14] ^= x[2]; x[14] = _rotl(x[14], 16)
        x[10] = (x[10] + x[14]) & M32; x[6] ^= x[10]; x[6] = _rotl(x[6], 12)
        x[2] = (x[2] + x[6]) & M32; x[14] ^= x[2]; x[14] = _rotl(x[14], 8)
        x[10] = (x[10] + x[14]) & M32; x[6] ^= x[10]; x[6] = _rotl(x[6], 7)

        x[3] = (x[3] + x[7]) & M32; x[15] ^= x[3]; x[15] = _rotl(x[15], 16)
        x[11] = (x[11] + x[15]) & M32; x[7] ^= x[11]; x[7] = _rotl(x[7], 12)
        x[3] = (x[3] + x[7]) & M32; x[15] ^= x[3]; x[15] = _rotl(x[15], 8)
        x[11] = (x[11] + x[15]) & M32; x[7] ^= x[11]; x[7] = _rotl(x[7], 7)

        x[0] = (x[0] + x[5]) & M32; x[15] ^= x[0]; x[15] = _rotl(x[15], 16)
        x[10] = (x[10] + x[15]) & M32; x[5] ^= x[10]; x[5] = _rotl(x[5], 12)
        x[0] = (x[0] + x[5]) & M32; x[15] ^= x[0]; x[15] = _rotl(x[15], 8)
        x[10] = (x[10] + x[15]) & M32; x[5] ^= x[10]; x[5] = _rotl(x[5], 7)

        x[1] = (x[1] + x[6]) & M32; x[12] ^= x[1]; x[12] = _rotl(x[12], 16)
        x[11] = (x[11] + x[12]) & M32; x[6] ^= x[11]; x[6] = _rotl(x[6], 12)
        x[1] = (x[1] + x[6]) & M32; x[12] ^= x[1]; x[12] = _rotl(x[12], 8)
        x[11] = (x[11] + x[12]) & M32; x[6] ^= x[11]; x[6] = _rotl(x[6], 7)

        x[2] = (x[2] + x[7]) & M32; x[13] ^= x[2]; x[13] = _rotl(x[13], 16)
        x[8] = (x[8] + x[13]) & M32; x[7] ^= x[8]; x[7] = _rotl(x[7], 12)
        x[2] = (x[2] + x[7]) & M32; x[13] ^= x[2]; x[13] = _rotl(x[13], 8)
        x[8] = (x[8] + x[13]) & M32; x[7] ^= x[8]; x[7] = _rotl(x[7], 7)

        x[3] = (x[3] + x[4]) & M32; x[14] ^= x[3]; x[14] = _rotl(x[14], 16)
        x[9] = (x[9] + x[14]) & M32; x[4] ^= x[9]; x[4] = _rotl(x[4], 12)
        x[3] = (x[3] + x[4]) & M32; x[14] ^= x[3]; x[14] = _rotl(x[14], 8)
        x[9] = (x[9] + x[14]) & M32; x[4] ^= x[9]; x[4] = _rotl(x[4], 7)
    return x


def chacha20_block(key, counter, nonce12):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += [counter & M32]
    state += list(struct.unpack("<3I", nonce12))
    x = _chacha_rounds(state)
    out = [(x[i] + state[i]) & M32 for i in range(16)]
    return struct.pack("<16I", *out)


def hchacha20(key, nonce16):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    x = _chacha_rounds(state)
    return struct.pack("<8I", x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15])


# ---------------------------------------------------------------- Poly1305
def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def xchacha20poly1305_encrypt(key, nonce24, plaintext, aad=b""):
    if len(key) != 32 or len(nonce24) != 24:
        raise ValueError("XChaCha20-Poly1305 key/nonce length")
    subkey = hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    poly_key = chacha20_block(subkey, 0, nonce12)[:32]

    out = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 64):
        ks = chacha20_block(subkey, counter, nonce12)
        block = plaintext[i:i + 64]
        out.extend(a ^ b for a, b in zip(block, ks))
        counter += 1
    ct = bytes(out)

    pad_aad = b"\x00" * ((16 - len(aad) % 16) % 16)
    pad_ct = b"\x00" * ((16 - len(ct) % 16) % 16)
    mac_data = (aad + pad_aad + ct + pad_ct
                + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct)))
    return ct + poly1305(poly_key, mac_data)


# ---------------------------------------------------------------- 封包
def hkdf_sha256(secret, salt, info, length=32):
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def normalize_path(url):
    # 对应客户端 secureapi.normalizeAPIPath: 取 path 部分，忽略 query。
    if "://" in url:
        url = url.split("://", 1)[1]
        url = url[url.find("/"):] if "/" in url else "/"
    url = url.strip()
    if "?" in url:
        url = url.split("?", 1)[0]
    if not url.startswith("/"):
        url = "/" + url
    return url or "/"


def build_envelope(method, path, payload, access_token):
    path = normalize_path(path)
    ts = int(time.time())

    request_id = os.urandom(16).hex()
    nonce_raw = os.urandom(24)
    nonce = b64u(nonce_raw)

    priv = os.urandom(32)
    pub_raw = x25519(priv, X25519_BASE)
    pub = pub_raw.hex()
    shared = x25519(priv, bytes.fromhex(SERVER_PUB_HEX))

    salt = hashlib.sha256(("%s:%d" % (request_id, ts)).encode()).digest()
    info = INFO_PREFIX + method.upper().encode() + b":" + path.encode()
    key = hkdf_sha256(shared, salt, info)

    ad = ("%s\n%s\n%s\n%d" % (method.upper(), path, request_id, ts)).encode()
    ciphertext = b64u(xchacha20poly1305_encrypt(key, nonce_raw, payload, ad))

    sign_msg = b"\x00".join([
        b"v1",
        method.upper().encode(),
        path.encode(),
        request_id.encode(),
        str(ts).encode(),
        nonce.encode(),
        pub.encode(),
        ciphertext.encode(),
        access_token.encode(),
    ])
    sign = b64u(hmac.new(key, sign_msg, hashlib.sha256).digest())

    body = json.dumps({
        "v": "v1",
        "request_id": request_id,
        "ts": ts,
        "nonce": nonce,
        "pub": pub,
        "ciphertext": ciphertext,
        "sign": sign,
    }, separators=(",", ":")).encode()
    return body


# ---------------------------------------------------------------- HTTP
def http_json(method, url, body=None, token=None, headers=None, timeout=25):
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "hyperdown-checkin/1.0")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        return {"_raw": text}


# ---------------------------------------------------------------- 状态
def load_state(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if state.get("access_token") and state.get("refresh_token"):
            return state
    access = os.environ.get("HYPERDOWN_ACCESS_TOKEN") or DEFAULT_ACCESS
    refresh = os.environ.get("HYPERDOWN_REFRESH_TOKEN") or DEFAULT_REFRESH
    if not access or not refresh:
        raise SystemExit(
            "缺少 token：请先运行 hyperdown-token.ps1 -WriteState 生成状态文件，"
            "或设置环境变量 HYPERDOWN_ACCESS_TOKEN / HYPERDOWN_REFRESH_TOKEN。"
        )
    state = {
        "access_token": access,
        "refresh_token": refresh,
        "access_token_expires_at": "",
        "refresh_token_expires_at": "",
    }
    save_state(path, state)
    return state


def save_state(path, state):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------- 业务
def refresh_tokens(state, path, verbose):
    if verbose:
        print("access token 已过期/失效，正在刷新 ...")
    body = json.dumps({"refresh_token": state["refresh_token"]},
                      separators=(",", ":")).encode()
    status, text = http_json("POST", API_BASE + "/auth/refresh", body)
    data = parse_json(text)
    if status != 200 or not data.get("ok"):
        err = (data.get("error") or {})
        print("刷新 token 失败: HTTP %d %s %s" % (
            status, err.get("code", ""), err.get("message", "")), file=sys.stderr)
        if status in (400, 401, 403):
            print("refresh token 可能已在别处被轮换失效。请重新从客户端登录态获取 token "
                  "并更新状态文件: %s" % path, file=sys.stderr)
        return False
    info = data.get("data") or {}
    state["access_token"] = info.get("access_token", state["access_token"])
    state["refresh_token"] = info.get("refresh_token", state["refresh_token"])
    state["access_token_expires_at"] = info.get("access_token_expires_at", "")
    state["refresh_token_expires_at"] = info.get("refresh_token_expires_at", "")
    save_state(path, state)
    if verbose:
        print("token 刷新成功，已保存到 %s" % path)
    return True


def checkin(state, path, verbose):
    exp = jwt_exp(state.get("access_token", ""))
    if exp and exp <= int(time.time()) + 60:
        if not refresh_tokens(state, path, verbose):
            return None

    for attempt in (1, 2):
        payload = b"{}"
        body = build_envelope("POST", CHECKIN_PATH, payload, state["access_token"])
        headers = {"X-Hyperdown-Secure": "v1"}
        status, text = http_json("POST", API_BASE + "/me/checkins", body,
                                 token=state["access_token"], headers=headers)
        data = parse_json(text)
        err = data.get("error") or {}
        code = err.get("code", "")

        need_refresh = (status == 401 or code in (
            "unauthorized", "token_expired", "auth_expired", "invalid_token"))
        if need_refresh and attempt == 1:
            if refresh_tokens(state, path, verbose):
                continue
            return None

        if status == 200 and data.get("ok"):
            return ("ok", data.get("data") or {})
        if code == "already_checked_in":
            return ("already", data.get("data") or {})
        return ("error", {"status": status, "code": code,
                          "message": err.get("message", text[:300])})
    return ("error", {"status": 0, "code": "retry_failed", "message": "重试失败"})


def show_status(state, path):
    try:
        if jwt_exp(state.get("access_token", "")) <= int(time.time()) + 60:
            refresh_tokens(state, path, True)
        status, text = http_json("GET", API_BASE + "/me", token=state["access_token"])
        data = parse_json(text)
        if status != 200 or not data.get("ok"):
            print("查询失败: HTTP %d %s" % (status, text[:300]), file=sys.stderr)
            return 1
        info = data.get("data") or {}
        print("账号: %s" % info.get("email", ""))
        print("今日已签到: %s" % ("是" if info.get("is_check_in") else "否"))
        print("累计签到: %s 天" % info.get("total_days_check_in", 0))
        print("最近签到: %s" % info.get("last_check_in_at", ""))
        print("可用流量: %.2f GB" % (int(info.get("traffic_bytes") or 0) / (1024 ** 3)))
        return 0
    except Exception as exc:
        print("查询异常: %s" % exc, file=sys.stderr)
        return 1


def selftest():
    # RFC 7748 X25519 测试向量
    alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = x25519(alice_priv, bob_pub).hex()
    ok1 = shared == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    alice_pub = x25519(alice_priv, X25519_BASE).hex()
    ok2 = alice_pub == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

    # 用客户端真实请求校验 XChaCha20-Poly1305
    key = bytes.fromhex("0036d954b202698e78f04ff317132126048fb096ddce579c2c9c5eae2546a928")
    nonce = bytes.fromhex("3edee4cfae6174802b215ed7a7c901e0729d84ff860a6e43")
    plaintext = b'{"code":"ZZTEST0004"}'
    ad = b"POST\n/api/v1/redemptions/redeem\n2ef8bdc9997555b85c6ebcc81e7ba585\n1792986583"
    expected = ("cffa8478b645f805fa2137f72666945f7542ce71b05bee79853dfdbb21f78c274"
                "016f79b1b")
    got = xchacha20poly1305_encrypt(key, nonce, plaintext, ad).hex()
    ok3 = got == expected

    print("X25519 shared :", "OK" if ok1 else "FAIL")
    print("X25519 pubkey :", "OK" if ok2 else "FAIL")
    print("XChaCha20 AEAD:", "OK" if ok3 else "FAIL", got)
    return 0 if (ok1 and ok2 and ok3) else 1


def main(argv):
    state_path = STATE_DEFAULT
    verbose = True
    mode = "checkin"

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--state" and i + 1 < len(argv):
            state_path = argv[i + 1]
            i += 2
            continue
        if arg in ("--quiet", "-q"):
            verbose = False
        elif arg in ("--status", "-s"):
            mode = "status"
        elif arg == "--selftest":
            return selftest()
        elif arg in ("--help", "-h"):
            print(__doc__ or "hyperdown-checkin.sh")
            return 0
        else:
            print("未知参数: %s" % arg, file=sys.stderr)
            return 2
        i += 1

    if mode == "status":
        state = load_state(state_path)
        return show_status(state, state_path)

    state = load_state(state_path)
    result = checkin(state, state_path, verbose)
    if result is None:
        return 1
    kind, info = result
    if kind == "ok":
        reward = int(info.get("reward_bytes") or info.get("traffic_added") or 0)
        if reward:
            print("签到成功，获得 %.2f GB 流量" % (reward / (1024 ** 3)))
        else:
            print("签到成功")
        return 0
    if kind == "already":
        print("今日已签到（无需重复）")
        return 0
    print("签到失败: HTTP %s %s %s" % (
        info.get("status"), info.get("code"), info.get("message")), file=sys.stderr)
    if info.get("code") == "secure_request_expired":
        print("提示: 本机时间与服务端偏差过大，请校准系统时间。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
PYEOF
