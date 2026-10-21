---
type: post
publish: true
title: LastPet
created: '2026-05-10'
author:
  - Rabjho
ctf: DDC2026
role: author
tags:
  - crypto
  - web
  - author
---
This challenge is based on the recent paper [Zero Knowledge (About) Encryption: A Comparative Security Analysis of Three Cloud-based Password Managers](https://eprint.iacr.org/2026/058), which analyses the claim that password manager providers cannot access client passwords/secrets. The paper does this by changing the threat model to one where the attacker has full control of the server.

The challenge implements LastPass' key hierarchy as described in the paper and gives players root access to the server, while a bot interacts with the server at regular intervals. If you haven't solved the challenge yet, I would recommend reading the paper and giving it another go. If you have solved the challenge but haven't read the paper, I can still recommend the read (or at least a skim).

The challenge can be solved in a few ways that exploit the same vulnerability. The below solution is just the one I feel explains the vulnerability best.

## LastPet

> Jeg har hørt, at gamificerede applikationer er gode til at få folk til at bruge dem, så jeg har lavet en Tamagochi-adgangskodehåndtering for at få flere til at oprette gode adgangskoder. Jeg kan selvfølgelig ikke se brugernes adgangskoder, så du burde nok kunne få root-adgang for at tjekke sikkerheden.

> Author: Rabjho (me)
>
> Category: crypto, web

The challenge handout gives us `client.py` and access to the server container with credentials `root:root`. I was quite nervous about unintended solves when handing out those privileges, and wrote this before the competition started, so let's see...

## Solution

### Using the client

Let's start by simply using the client to understand its functionality. We can look at the code afterwards.

First, we make an account:

```
██╗      █████╗ ███████╗████████╗██████╗ ███████╗████████╗
██║     ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔════╝╚══██╔══╝
██║     ███████║███████╗   ██║   ██████╔╝█████╗     ██║
██║     ██╔══██║╚════██║   ██║   ██╔═══╝ ██╔══╝     ██║
███████╗██║  ██║███████║   ██║   ██║     ███████╗   ██║
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚══════╝   ╚═╝


  [1] Login
  [2] Register
  [0] Exit
  > 2

  Username:         Rabjho
  Master password:

  Registered! Please log in.

  Press enter to continue...
```

After logging in we can view and add *pets* to our *zoo* - in other words, items to our vault. If we add a pet with the necessary fields and then view our vault, we will see something like this. Each pet has an ASCII picture along with the fields we filled out, plus two new fields: *mood* and *extinction*. These will become relevant shortly.

```
============================================

   (\(\
   ( -.-)
   o_(")_(")

  Name:        MyPet
  Mood:        sad 😟
  Extinction:  Extinct
  Username:    MyUsername
  Password:    Mypasswd
  URL:         example.com
============================================
```

### Inspecting the client

The client has quite a lot of code. Most of it is just flavour or infrastructure. Let's walk through the relevant parts.

At the top of `client.py` we find the key derivation and encryption code. The key derivation uses PBKDF2 with SHA-256 and 600,000 iterations to produce the master key. The authentication key is derived by doing one additional iteration on top of that. Encryption is standard AES-256-CBC (lines 25–48).

Further down we find the logic for the *mood* and *extinction* fields — the gamification features:

- **Mood** is a gamified measure of password strength, calculated entirely client-side.
- There is also a feature to check if a pet has been **poached** (i.e. the password has been found in a breach). The client sends the first five characters of the password's SHA-1 hash to the server, which responds with all known hashes that share that prefix (from a subset of `rockyou.txt`). This is the same k-anonymity approach that [HaveIBeenPwned](https://haveibeenpwned.com/) uses.
- **Extinction** is fetched from the server based on the **decrypted** URL. This is the key detail for the primary solution.

```py
def render_pet(item: dict, k_u: bytes) -> None:

    name = item["name"]
    username = decrypt_field(item["fields"]["username"], k_u)
    password = decrypt_field(item["fields"]["password"], k_u)
    url = decrypt_field(item["fields"]["url"], k_u) # Decrypts url
    extinction_tier = fetch_extinction(extract_domain(url))
    poached = fetch_poached(password) # Sends prefix to the server
    ...
```

The `fetch_poached` function sends the SHA-1 prefix to the server:

```py
def fetch_poached(password: str) -> bool:
    password_hash = hashlib.sha1(password.encode()).hexdigest()
    prefix = password_hash[:5]

    try:
        r = requests.get(f"{SERVER}/poached/{prefix}", timeout=5)
        entries = r.json().get("entries", [])
    except Exception as e:
        print(f"  [!] Error fetching poaching data: {e}")
        return False

    for entry in entries:
        if entry["hash"] == password_hash:
            return True
    return False
```

Take note of the `fetch_extinction` call. The client decrypts the URL field and sends the plaintext domain to the server. This is our primary attack vector.

### Enumerating the server

Since we have root access, let's poke around. The application lives in `/app/`:

```bash
root@f2adbda95eb2:/app# ls -la
total 3200
drwxr-xr-x 1 root root    4096 May  8 11:13 .
drwxr-xr-x 1 root root    4096 May  8 11:13 ..
drwxr-xr-x 2 root root    4096 May  8 11:13 __pycache__
-rw-r--r-- 1 root root    1194 May  8 11:22 access.logs
-rwxrwxrwx 1 root root     155 Apr 28 04:24 entrypoint.sh
-rwxrwxrwx 1 root root 3236838 Apr 28 04:24 rainbow_table.json
-rwxrwxrwx 1 root root    5596 Apr 28 04:24 server.py
-rwxrwxrwx 1 root root    1877 Apr 28 04:24 top-domains.csv
drwxr-xr-x 2 root root    4096 May  8 11:15 zoos
```

`server.py` is a standard Flask app served by Gunicorn. Importantly, **the server never touches the master key** used for encryption. It practically only handles authentication, stores encrypted vaults as JSON files, and provides endpoints for looking up website popularity and password leaks.

Looking at `access.logs`, we find our next piece of the puzzle:

```log
root@f2adbda95eb2:/app# cat access.logs
2026-05-08 11:14:06,493 INFO GET /pets/karlkoder status=200
2026-05-08 11:14:36,883 INFO GET /pets/karlkoder status=200
2026-05-08 11:15:07,410 INFO GET /pets/karlkoder status=200
2026-05-08 11:15:37,808 INFO GET /pets/karlkoder status=200
2026-05-08 11:16:04,408 INFO GET /pets/Rabjho status=200
2026-05-08 11:16:08,205 INFO GET /pets/karlkoder status=200
2026-05-08 11:16:38,555 INFO GET /pets/karlkoder status=200
2026-05-08 11:17:08,919 INFO GET /pets/karlkoder status=200
2026-05-08 11:17:39,265 INFO GET /pets/karlkoder status=200
2026-05-08 11:17:43,665 INFO GET /pets/Rabjho status=200
```

There is another user, `karlkoder`, who regularly accesses their vault. We can also inspect their encrypted vault directly at `/app/zoos/karlkoder.json`.

### The vulnerability: malleable encrypted fields

Here is the core insight. The encrypted fields have **no authentication** (plain AES-CBC, no HMAC or GCM), and **the same key is reused** for all fields in the vault. This means we can freely swap ciphertext between fields.

Recall that when the client renders a pet, it decrypts the URL field and sends the plaintext to the server via the `/extinction/<url>` endpoint. So if we take the ciphertext from the *password* field and copy it into the *url* field in `karlkoder.json`, the client will happily decrypt the password, think it's a URL, and send it in plaintext to the server.

### Patching the server to capture the leak

To actually read the leaked plaintext, we need to patch `server.py` so that the `/extinction/<url>` endpoint logs the incoming URL. A one-liner will do:

```py
@app.get("/extinction/<path:url>")
def extinction(url):
    tier = URL_TO_TIER.get(url, "Extinct")
    access_logger.info(url)  # We add this line
    return jsonify({"url": url, "tier": tier})
```

Looking at `entrypoint.sh`, we can see it automatically restarts Gunicorn if it ever dies:

```bash
root@f2adbda95eb2:/app# cat entrypoint.sh
#!/bin/bash

/usr/sbin/sshd -D &

while true; do
    gunicorn --bind 0.0.0.0:80 server:app
    echo "Gunicorn exited, restarting in 1s..."
    sleep 1
done
```

So we can simply kill the running Gunicorn processes and let `entrypoint.sh` restart the server with our patched code:

```bash
root@f2adbda95eb2:/app# ps aux | grep gunicorn
root         8  0.0  0.3 112236 29680 ?        Sl   11:13   0:00 /usr/local/bin/python3.13 /usr/local/bin/gunicorn --bind 0.0.0.0:80 server:app
root         9  0.0  0.8  79308 67660 ?        S    11:13   0:01 /usr/local/bin/python3.13 /usr/local/bin/gunicorn --bind 0.0.0.0:80 server:app
root      1266  0.0  0.0   3500  1792 pts/0    S+   11:48   0:00 grep gunicorn
root@f2adbda95eb2:/app# kill 8 9
```

### Getting the flag

After the server restarts with our patch and `karlkoder`'s bot accesses the vault again, we can see the decrypted URLs appearing in the logs:

```log
2026-05-08 11:50:12,946 INFO GET /pets/karlkoder status=200
2026-05-08 11:50:43,343 INFO GET /pets/karlkoder status=200
2026-05-08 11:51:13,817 INFO GET /pets/karlkoder status=200
2026-05-08 11:51:13,820 INFO 0dayaarhus.dk
2026-05-08 11:51:13,825 INFO brunnerne.dk
2026-05-08 11:51:13,830 INFO jutlandia.club
2026-05-08 11:51:13,836 INFO dtu.dk
2026-05-08 11:51:13,841 INFO cybermesterskaberne.dk
```

These are the decrypted URLs from `karlkoder`'s vault. To get the flag, we swap the *password* ciphertext into the *url* field for the entry labelled "Flag hording service" in `karlkoder.json`, and wait for the bot to access the vault again. The decrypted password, which is the flag, will appear in `access.logs`.

### Tl;Dr


1. We have root on the server and can read/modify all data except the encryption key.
2. The encrypted vault fields use AES-CBC with no integrity check and a shared key, making the ciphertext trivially swappable between fields.
3. The client leaks the decrypted URL to the server via the `/extinction/<url>` endpoint.
4. We swap the password ciphertext into the URL field in the target user's vault.
5. We patch the server to log requests to `/extinction/`.
6. When the bot renders its vault, the password is decrypted as a "URL" and sent to our patched server in plaintext - giving us the flag.

![[megamind.png]]
