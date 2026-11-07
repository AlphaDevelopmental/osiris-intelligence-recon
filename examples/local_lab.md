# Testing active mode in an isolated local lab

Loopback (127.0.0.0/8), link-local and multicast addresses are never allowed, even with
`--lab-mode`. Use a container or VM on an RFC1918 address you control:

```bash
# 1. Isolated Docker network and a disposable web server on it
docker network create --subnet 172.30.0.0/24 osiris-lab
docker run --rm -d --name lab-web --network osiris-lab --ip 172.30.0.10 httpd:2.4

# 2. Scope file naming only that address
echo "172.30.0.10" > /tmp/lab-scope.txt

# 3. Preview (sends nothing), then run. --lab-mode permits the private address.
python3 osiris_recon.py --target 172.30.0.10 --mode active --enable-active \
  --scope /tmp/lab-scope.txt --authorization LAB-LOCAL-001 --lab-mode --no-scanner --dry-run
python3 osiris_recon.py --target 172.30.0.10 --mode active --enable-active \
  --scope /tmp/lab-scope.txt --authorization LAB-LOCAL-001 --lab-mode --no-scanner

# 4. Clean up
docker stop lab-web && docker network rm osiris-lab
```

Passive OSIRIS lookups for a private address return little or nothing (the public
services cannot see it); the useful output is the active HTTP/TLS analysis and the
audit log in `reports/172.30.0.10/active_audit.jsonl`.

The automated test suite exercises active mode with mocks only and never needs this lab.
