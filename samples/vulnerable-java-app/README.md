# vulnerable-java-app

A deliberately insecure servlet app used to demo `secpipe` and to drive its integration tests.
**Do not deploy it.** Every vulnerability is seeded on purpose, and each file also contains safe code
that must *not* be flagged.

```bash
secpipe scan samples/vulnerable-java-app
```

| File | Seeded issue | Expected finding | Safe code that must not be flagged |
|---|---|---|---|
| `LoginServlet.java` | Request parameters concatenated into SQL; DB password literal; `printStackTrace` | CWE-89 (critical), CWE-798, CWE-209 | |
| `UserDao.java` | Method parameter concatenated into SQL | CWE-89 | `findByIdSafe` (PreparedStatement) |
| `FileDownloadServlet.java` | Request parameter used as a file name | CWE-22 | |
| `PingServlet.java` | Request parameter passed to `Runtime.exec` | CWE-78 (critical) | `uptime` (constant command) |
| `JwtUtil.java` | Hard-coded HMAC signing key | CWE-321 | |
| `CryptoUtil.java` | MD5 password hash; DES/ECB | CWE-328, CWE-327 | `checksum` (SHA-256) |
| `SessionRestoreServlet.java` | `ObjectInputStream` on the request body | CWE-502 (critical) | |
| `AppConfig.java` | AWS access key literal | CWE-798 | `PASSWORD_PARAM`, `PASSWORD_FIELD_LABEL` |
| `pom.xml` | `log4j-core` 2.14.1, `commons-collections` 3.2.1 | CVE-2021-44228 (Log4Shell) and related, CVE-2015-7501 | `junit` (test scope, excluded) |
