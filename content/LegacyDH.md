---
type: post
publish: true
title: LegacyDH
created: '2026-05-10'
author:
  - Rabjho
ctf: DDC2026
role: author
tags:
  - crypto
  - forensics
  - author
---
![[low_high_cortisol.png]]

Classic crypto challenge using classic schemes but with a forensics and legacy software twist.

## LegacyDH

> Vi installerede Diffie Hellman med en ret dårlig prime og kan ikke opgradere serveren på grund af ældre versioner. Vi har lige opgraderet den gamle NemDH-klient til MitDH-klienten, og vi håber, at modstanderen ikke fik trafik fra de gamle klienter for at gendanne det flag, der var krypteret af serveren!

> Author: dfaranha, Rabjho (me)
>
> Category: crypto, forensics

The challenge supplies a network capture `traffic.pcap` which contains traffic from a few different clients using two different versions, where one is a legacy client. Both clients are supplied.

### Diffing the clients

When we diff both the two clients in the handout, we notice that the new client implements safeguards against small prime factors. This hints further that the server may use unsafe public keys.

```diff
3c3
< NemDH client for Diffie-Hellman key exchange.
---
> MitDH client for Diffie-Hellman key exchange.
16c16
< class NemDH:
---
> class MitDH:
25a26,40
>     def _find_small_factors(self, n, limit=1000):
>         """Find small prime factors of n up to limit"""
>         factors = []
>         temp = n
>
>         for p in range(2, limit + 1):
>             if temp % p == 0:
>                 count = 0
>                 while temp % p == 0:
>                     temp //= p
>                     count += 1
>                 factors.append((p, count))
>
>         return factors, temp  # Returns factors found and remaining cofactor
>
53a69,110
>         # Factor-based structural checks
>
>         p_minus_1 = p - 1
>         small_factors, cofactor = self._find_small_factors(p_minus_1, limit=10000)
>
>         if small_factors:
>             # Aggregate discovered factors
>
>             small_product = 1
>             for prime, exp in small_factors:
>                 small_product *= prime**exp
>
>             test_value = pow(server_public, small_product, p)
>
>             if test_value == 1:
>                 order = self._compute_element_order(
>                     server_public, p, max_order=small_product
>                 )
>                 return False, f"Public key lies in small subgroup of order {order}"
>
>             if cofactor < 2**128:
>                 return (
>                     False,
>                     f"Prime has weak structure: large factor is only {cofactor.bit_length()} bits",
>                 )
>
>         # Quick checks against tiny factors
>         small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727 ]
>
>         for q in small_primes:
>             if p_minus_1 % q == 0:
>                 exponent = p_minus_1 // q
>                 if pow(server_public, exponent, p) == 1:
>                     actual_order = self._compute_element_order(
>                         server_public, p, max_order=q
>                     )
>                     if actual_order and actual_order <= q:
>                         return (
>                             False,
>                             f"Public key has small order {actual_order} (divides {q})",
>                         )
>
79a137,153
>             # Validate server public key
>             is_valid, reason = self._validate_public_key(server_public, self.p, self.g)
>
>             if not is_valid:
>                 print(f"[!] REJECTING connection: {reason}")
>
>                 # Send rejection message
>                 reject_msg = {
>                     "client_version": "MitDH",
>                     "status": "rejected",
>                     "reason": reason,
>                 }
>                 reject_json = json.dumps(reject_msg).encode()
>                 sock.sendall(struct.pack(">I", len(reject_json)))
>                 sock.sendall(reject_json)
>                 return False
>
86c160
<                 "client_version": "NemDH",
---
>                 "client_version": "MitDH",
112d185
<
124c197
<     client = NemDH(host, port)
---
>     client = MitDH(host, port)
127c200
<     print("NemDH - DH Client")
---
>     print("MitDH - DH Client")
```

### The vulnerability

The new MitDH client validates the server's public key to ensure it doesn't lie in a small subgroup. The old NemDH client does none of this - it blindly accepts whatever the server sends. This means that if the server happens to use a prime $p$ where $p-1$ has small factors, and the server's public key falls into a small subgroup, the shared secret is confined to a small set of values. We can just brute-force it.

More concretely: in a standard Diffie-Hellman exchange, the shared secret is $s = g_s^{x_c} \mod p$. If the order of $g_s$ is small (say, at most 727 - the largest prime the MitDH client checks for), then $s$ can only take on a small number of values regardless of $x_c$. We can simply try all of them.

### Parsing the pcap

The traffic capture contains multiple connections. Each connection exchanges JSON messages over TCP: First the DH parameters (`p`, `g`, `server_public`), then the client's response (including `client_version`), and finally an encrypted message from the server (`encrypted_data`, `nonce`).

We need to:

1. Identify which connections used the legacy NemDH client (since those are the ones without subgroup validation).
2. Extract the DH parameters and the encrypted message from each of those connections.
3. Brute-force the shared secret.

### Solve script

The encryption uses AES-CTR, keyed with the SHA-256 hash of the shared secret. Since the shared secret lives in a small subgroup, we iterate over all possible powers of $g_s \mod p$ and check if the resulting decryption contains the flag prefix.

Solve script by dfaranha:

```python
from Crypto.Cipher import AES
import hashlib
from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
import json

TARGET_VERSION = "NemDH"

def try_parse_json(payload):
    try:
        text = payload.decode("utf-8", errors="ignore").strip()
        return json.loads(text)
    except Exception:
        return None

def normalize_flow(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]
    a = (ip.src, tcp.sport)
    b = (ip.dst, tcp.dport)
    return tuple(sorted([a, b]))

def extract_relevant_connections(packets):
    conns = set()
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue
        data = try_parse_json(payload)
        if not data:
            continue
        if data.get("client_version") == TARGET_VERSION:
            conns.add(normalize_flow(pkt))
    return conns

def group_json_traffic(packets, interesting_conns):
    grouped = defaultdict(list)
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        key = normalize_flow(pkt)
        if key not in interesting_conns:
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue
        data = try_parse_json(payload)
        if not data:
            continue
        grouped[key].append(data)
    return grouped

def extract_fields_per_connection(grouped):
    results = {}
    for key, messages in grouped.items():
        first_params = None
        enc_messages = []
        for msg in messages:
            if "p" in msg and "server_public" in msg:
                first_params = {
                    "p": msg["p"],
                    "server_public": msg["server_public"]
                }
            if "encrypted_data" in msg and "nonce" in msg:
                enc_messages = {
                    "encrypted_data": msg["encrypted_data"],
                    "nonce": msg["nonce"]
                }
        results[key] = {
            "params": first_params,
            "ciphertext": enc_messages
        }
    return results

def solve(p, server_public, encrypted_hex, nonce_hex):
    encrypted = bytes.fromhex(encrypted_hex)
    nonce = bytes.fromhex(nonce_hex)
    for exp in range(1, 728):
        candidate = pow(server_public, exp, p)
        key = hashlib.sha256(
            candidate.to_bytes((candidate.bit_length() + 7) // 8, "big")
        ).digest()
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(encrypted)
        if b"DDC" in plaintext:
            return plaintext

def main(pcap_file):
    packets = rdpcap(pcap_file)
    conns = extract_relevant_connections(packets)
    grouped = group_json_traffic(packets, conns)
    extracted = extract_fields_per_connection(grouped)
    print(f"[+] Processed {len(extracted)} connections\n")
    for key, data in extracted.items():
        print("=" * 70)
        print(f"Connection: {key[0]} <-> {key[1]}")
        if data["params"]:
            print(f"p = {data['params']['p']}")
            print(f"server_public = {data['params']['server_public']}")
        else:
            print("\n[-] No (p, server_public) message found")
            continue
        if data["ciphertext"]:
            print(f"encrypted_data = {data['ciphertext']['encrypted_data']}")
            print(f"nonce = {data['ciphertext']['nonce']}")
        else:
            print("\n[-] Less than 3 encrypted messages found")
            continue

        p = int(data['params']['p'], 16)
        server_public = int(data['params']['server_public'], 16)
        ciphertext = data['ciphertext']['encrypted_data']
        nonce = data['ciphertext']['nonce']
        if solve(p, server_public, ciphertext, nonce):
            print(solve(p, server_public, ciphertext, nonce))
            exit(0)

if __name__ == "__main__":
    main("traffic.pcap")
```

### Tl;Dr

1. The challenge provides a pcap and two DH client versions. The new client (MitDH) validates that the server's public key doesn't have a small order; the old client (NemDH) doesn't.
2. We filter the pcap for connections that used the legacy NemDH client.
3. For those connections, the server's public key lies in a small subgroup, so the shared secret can only take a handful of values.
4. We brute-force through all possible shared secrets (at most 727 candidates), derive the AES key, and decrypt. One of the connections contains the flag.
