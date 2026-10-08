# Scanner denylist coverage — and a negative result

19 standard-library callables that perform network, filesystem, process or dynamic-code operations, each built into a one-pickle probe artifact, plus **6 benign controls** (harmless stdlib calls a legitimate pickle makes). Nothing is weaponised: every host is under `.invalid` and every filesystem target is harmless or absent.

| measure | result |
|---|---|
| picklescan 1.0.5 flagged the 19 operation probes | **10/19** |
| fickling 0.1.12 flagged them | **19/19** |
| Quarantine observed the operation | **19/19** |
| **both scanners clean AND the operation observed** | **0** |
| picklescan called the benign controls infected (its own verdict) | **2/6** |
| picklescan flagged them *suspicious* without calling them infected | 3/6 |
| fickling false positives on the benign controls | **6/6** |
| Quarantine false positives on the benign controls | **0/6** |

## The negative result, stated plainly

**We set out to find a callable that reaches the network or the filesystem while both
scanners report clean, and we did not find one.** Their denylists cover direct calls to
the standard-library primitives in this set, and picklescan reads inside zip archives too.
On the benign controls picklescan flagged 2/6 and fickling 6/6, so the 100% above is denylist coverage rather than blanket suspicion.

That is why this project does **not** claim a scanner bypass. The measured difference is
**coverage of the code path**: the payloads that neither scanner opens live in
`custom_generate/generate.py` and `modeling_*.py`, not in a pickle. See `reports/corpus-eval.md`.

## Per callable

| callable | kind | picklescan | fickling | Quarantine |
|---|---|---|---|---|
| `socket.gethostbyname` | network | **clean** | flagged | observed |
| `socket.gethostbyaddr` | network | **clean** | flagged | observed |
| `socket.getfqdn` | network | flagged | flagged | observed |
| `socket.getaddrinfo` | network | flagged | flagged | observed |
| `socket.create_connection` | network | flagged | flagged | observed |
| `ssl.get_server_certificate` | network | flagged | flagged | observed |
| `http.client.HTTPConnection` | network | **clean** | flagged | observed |
| `urllib.request.urlopen` | network | flagged | flagged | observed |
| `ftplib.FTP` | network | **clean** | flagged | observed |
| `smtplib.SMTP` | network | **clean** | flagged | observed |
| `poplib.POP3` | network | **clean** | flagged | observed |
| `imaplib.IMAP4` | network | **clean** | flagged | observed |
| `xmlrpc.client.ServerProxy` | network | **clean** | flagged | observed |
| `builtins.open` | filesystem | **clean** | flagged | observed |
| `pathlib.Path.read_text` | filesystem | flagged | flagged | observed |
| `os.remove` | filesystem | flagged | flagged | observed |
| `subprocess.Popen` | process | flagged | flagged | observed |
| `os.popen` | process | flagged | flagged | observed |
| `builtins.eval` | dynamic_code | flagged | flagged | observed |
| `json.dumps (control)` | benign | **clean** | flagged | nothing |
| `math.sqrt (control)` | benign | **clean** | flagged | nothing |
| `collections.OrderedDict (control)` | benign | **clean** | flagged | nothing |
| `datetime.datetime.now (control)` | benign | flagged | flagged | nothing |
| `os.getcwd (control)` | benign | flagged | flagged | nothing |
| `re.compile (control)` | benign | **clean** | flagged | nothing |

Every payload is a benign probe: hostnames are under `.invalid` (RFC 2606) and no filesystem target is harmed. This measures denylist coverage, not an exploit.
