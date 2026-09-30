# secpipe: Defensive Security Analysis Pipeline (Java)

`secpipe` is a command-line tool that scans a Java codebase and its third-party dependencies for security
vulnerabilities. It maps every finding to **CWE**, **CVE** and the **OWASP Top 10 (2021)**, ranks findings by
risk, suggests fixes, generates **JUnit 5 security regression tests**, and writes one unified report. The
report comes as Excel-ready CSV, HTML dashboard, Markdown, JSON and SARIF.

It is the MVP for the SYSC 4907 project *Defensive Security Analysis Pipeline*. A small team of cooperating
agents does the work, and existing analyzers plug in behind a single adapter interface. Later versions can
add a GitHub Action and more tools without changing the core.

```
$ secpipe scan samples/vulnerable-java-app

Scan complete: 22 finding(s) in 1.9 s
  CRITICAL 6   HIGH     8   MEDIUM   7   LOW      1   INFO     0
  code: 12   dependencies: 10   project: 8 files, 3 dependencies

  ID      SEVERITY SCORE  FINDING                                     LOCATION
  SP-001  CRITICAL  10.0  CWE-89 SQL injection                        src/main/java/com/example/vulnlab/LoginServlet.java:27
  SP-002  CRITICAL  10.0  CWE-78 OS command injection                 src/main/java/com/example/vulnlab/PingServlet.java:16
  SP-005  CRITICAL   8.5  CVE-2021-44228 in log4j-core 2.14.1         pom.xml
  ...
Analyzers: builtin ok (11), pmd ok (2), semgrep skipped, osv ok (10), trivy skipped, grype skipped
Timings:   profile 11 ms, parse-and-map 164 ms, code-analysis 573 ms, dependency-analysis 1.6 s, ...
Reports:   secpipe-out/report.html  report.md  report.json  findings.csv  report.sarif
Regression tests: 13 file(s) in secpipe-out/generated-tests
Result: FAIL - 14 finding(s) at or above HIGH (--fail-on high)
```

## Install and first scan

The only requirement is **JDK 21+**. Maven is not needed: the bundled Maven wrapper downloads it on the
first build.

```bash
git clone <this repo> && cd <repo>
./install.sh                     # builds target/secpipe.jar, links `secpipe` into ~/.local/bin
secpipe doctor                   # checks JDK, build tools, optional analyzers, network, AI settings
secpipe scan samples/vulnerable-java-app
```

To run without installing:

```bash
./mvnw -q package -DskipTests
./bin/secpipe scan samples/vulnerable-java-app     # Windows: bin\secpipe.cmd scan ...
# or: java -jar target/secpipe.jar scan samples/vulnerable-java-app
```

After the scan, open `secpipe-out/report.html` in a browser, or `secpipe-out/findings.csv` in Excel.

## Commands

| Command | Purpose |
|---|---|
| `secpipe scan [PATH]` | Scan a project (default: current directory) and write reports plus generated tests to `secpipe-out/`. |
| `secpipe verify [PATH] -b secpipe-out/report.json` | Re-scan after a fix and report each baseline finding as **fixed** or **still present**, plus anything **new**. |
| `secpipe doctor [PATH]` | Explain what is installed, what is optional, and what to do about anything missing. |

Common options (shared by `scan` and `verify`; see `secpipe scan --help` for all):

| Option | Meaning |
|---|---|
| `-l, --lang java` | Language of the codebase (FR1). Only `java` is supported in the MVP. |
| `-c, --category code\|deps\|all` | Analyze source code, dependencies, or both (FR1). Default `all`. |
| `-f, --format md,html,json,csv,sarif` | Which reports to write. Default: all. |
| `-o, --out DIR` | Output directory. Default `secpipe-out`. |
| `--fail-on critical\|high\|medium\|low\|info\|none` | Exit with code 1 when a finding is at or above this severity. Default `high`. |
| `--tools ID,...` / `--exclude-tools ID,...` | Choose analyzers (`builtin`, `pmd`, `semgrep`, `osv`, `trivy`, `grype`). |
| `--deps-from auto\|build\|manifest` | Resolve dependencies with Maven/Gradle (full transitive tree) or by reading `pom.xml`/`build.gradle`. `auto` tries the build tool first. |
| `--offline` | Do not call OSV.dev; use cached advisories only. |
| `--no-ai` | Deterministic agents only, even if an LLM is configured. |
| `--no-tests` | Skip regression-test generation. |
| `--include-tests` | Also scan `src/test/**`. |
| `-q` / `-v` | Quiet (summary only) / verbose (debug output and stack traces). |

**Exit codes:** `0` means no findings at or above `--fail-on`. `1` means there are findings at or above
`--fail-on`; for `verify`, it means such findings remain or were introduced. `2` means a usage or
environment error. Every error message includes a hint on how to fix it.

## Outputs

| File | What it is |
|---|---|
| `report.html` | Self-contained dashboard: severity counts, filters, search, and a detail view with explanation, fix and generated test. Works offline. |
| `findings.csv` | One row per finding with ID, severity, score, CWE, OWASP, CVE, file and line, package and versions, fix, test and fingerprint. UTF-8 with BOM so Excel opens it directly (FR3). |
| `report.md` | Readable summary for PRs, wikis or email. |
| `report.json` | Full machine-readable result. It is also the **baseline** for `secpipe verify`. |
| `report.sarif` | SARIF 2.1.0 for GitHub code scanning, IDEs and other SARIF viewers. |
| `generated-tests/` | JUnit 5 security regression tests. There is one per code finding plus a dependency-version test (FR5). |

### Generated regression tests

Copy `secpipe-out/generated-tests/src/test/java/secpipe/` into your project's `src/test/java/` and run
`./mvnw test`. The tests need `junit-jupiter` (including `junit-jupiter-params`) as a test dependency.

- Each test **fails while the vulnerability is present** and passes once it is fixed. After that it guards
  against regressions. The test checks that the flagged statement is gone and that the vulnerable pattern
  for that CWE does not reappear without a recognised mitigation.
- Each test also carries a `@Disabled` **behavioural test** with attack payloads for the CWE (for example
  `' OR '1'='1` or `../../etc/passwd`). Wire it to your code and enable it.
- `DependencyVersionsSecurityTest` fails while a vulnerable library version is on the test classpath.

The integration test `VerifyIntegrationTest` runs the whole loop. It scans the sample, runs the generated SQL
injection test (which fails), applies a `PreparedStatement` fix, and runs the test again (which passes). It then
runs `secpipe verify`, which reports 1 fixed, 0 new.

## How it works

`OrchestratorAgent` profiles the project, then runs the specialist agents. Code analysis and dependency
analysis run in parallel.

```
                 ┌──────────────────────────── OrchestratorAgent ─────────────────────────────┐
 project ──►  profile (build tool, sources, manifests) ──► parse + code map (endpoints, frameworks)
                 │
                 ├─► CodePatternAgent ── builtin rules (JavaParser, taint-aware) · PMD · Semgrep*
                 └─► DependencyAgent  ── Maven/Gradle/pom resolution ──► OSV.dev · Trivy* · Grype*
                 │
                 ▼
            KnowledgeAgent      CWE ↔ OWASP Top 10 mapping, explanations, fix guidance (bundled catalogs)
            ExploitabilityAgent reachable from HTTP input? parameter only? constant? (+ optional LLM review)
            TriageAgent         merge duplicates across tools, score = severity × confidence × exploitability
            TestGenAgent        per-CWE JUnit 5 regression tests (+ optional LLM-written behavioural test)
            ReportAgent         html · csv · md · json · sarif · terminal summary
                 └──────────────────────────────────────────────────────────────────────────────┘
 * optional: used automatically when installed on PATH
```

- **Built-in rules** need no external tool, so the first scan always works. They use a lightweight
  intra-procedural taint tracker that distinguishes HTTP request input, method parameters and constants.
  This keeps false positives low: a constant query or a `PreparedStatement` is not flagged. Covered:
  SQL injection (CWE-89), path traversal (CWE-22), OS command injection (CWE-78), hard-coded
  credentials and keys (CWE-798 / CWE-321), weak hashes and ciphers or old TLS (CWE-328 / CWE-327), and
  unsafe deserialization (CWE-502).
- **PMD 7** runs embedded, with its security ruleset plus a few related rules.
- **Dependencies** are resolved with `mvn dependency:list` or `gradle dependencies` when available; that
  includes transitive dependencies. Otherwise `secpipe` parses `pom.xml` (properties and `dependencyManagement`)
  or `build.gradle` directly. The packages are checked against **OSV.dev**, which aggregates the GitHub Advisory
  Database, NVD and others. Responses are cached in `~/.secpipe/cache` for repeat and `--offline` scans.
- **Scoring:** severity weight (critical 10, high 7.5, medium 5, low 2.5, info 1) × confidence
  (high 1, medium 0.75, low 0.5) × exploitability (likely 1, possible 0.85, unknown 0.8, unlikely 0.5).
  Findings reported by more than one tool get a confidence boost.
- **Fingerprints** hash the CWE, the file and the normalized flagged statement, so `verify` is not
  fooled by unrelated edits that only shift line numbers.

### Optional AI assistance

Without an LLM, every agent uses deterministic heuristics, so no setup or keys are needed. To let agents
review exploitability, tailor fixes and write behavioural tests with an LLM, point `secpipe` at any
OpenAI-compatible endpoint:

```bash
export SECPIPE_LLM_KEY=sk-...                    # or OPENAI_API_KEY
export SECPIPE_LLM_MODEL=gpt-4o-mini             # optional (default)

# or a local model, no key needed:
export SECPIPE_LLM_URL=http://localhost:11434/v1 # Ollama; default model llama3.1
```

At most `--ai-max` findings (default 15), highest risk first, are sent to the LLM, along with only the
surrounding code snippet. If the endpoint fails repeatedly, `secpipe` falls back to heuristics and says
so. `--no-ai` disables the LLM entirely.

### Other environment variables

| Variable | Purpose |
|---|---|
| `SECPIPE_OSV_URL` | Alternative OSV API base URL (mirror or proxy). |
| `SECPIPE_CACHE_DIR` | Cache directory (default `~/.secpipe/cache`). |
| `SECPIPE_SEMGREP_CONFIG` | Semgrep ruleset (default `p/java`). |

## Extending

**Add an analyzer (NFR4).** Implement `ca.carleton.secpipe.tools.ScannerAdapter` and register it in
`ToolRegistry.defaults()`:

```java
public class SpotBugsAdapter implements ScannerAdapter {
    public String id() { return "spotbugs"; }
    public String displayName() { return "SpotBugs + FindSecBugs"; }
    public Category category() { return Category.CODE; }
    public boolean isAvailable() { return Proc.which("spotbugs").isPresent(); }
    public String unavailableReason() { return "spotbugs not on PATH"; }
    public boolean supports(ProjectProfile p) { return "java".equals(p.language()); }
    public List<Finding> run(ScanContext ctx) throws ScanException {
        // run the tool, map each result to Finding.code(id(), ruleId, file, line) with CWE + severity
    }
}
```

After that, the adapter shows up in `doctor` and in the tool selection flags. Its findings are also
deduplicated against other tools, mapped to OWASP, scored, tested and reported, with no other changes.

**Add a built-in rule.** Implement `JavaRule` in `tools/builtin` and add it to `BuiltinRulesAdapter`. Add a
CWE entry to `knowledge/cwe-subset.json` and a test template to `knowledge/test-templates.json` if needed.

**Add a report format.** Implement `report.ReportWriter` and add it to `Reports.ALL`.

## Project layout

```
bin/secpipe, bin/secpipe.cmd   launchers (check for Java 21+ with a clear message)
install.sh                     build + link into ~/.local/bin
src/main/java/ca/carleton/secpipe/
  cli/        scan, verify, doctor (picocli)
  agents/     orchestrator + specialist agents
  tools/      ScannerAdapter, ToolRegistry, PMD/Semgrep/OSV/Trivy/Grype adapters, builtin rules, dependency resolution
  knowledge/  CWE + OWASP Top 10 catalogs
  llm/        OpenAI-compatible client with a no-op fallback
  report/     html, csv, md, json, sarif, verify reports
samples/vulnerable-java-app/   deliberately vulnerable app used for demos and integration tests
```

## Development

```bash
./mvnw test          # 43 unit + integration tests; OSV is mocked, so no network is needed
./mvnw package       # target/secpipe.jar (self-contained)
```

## Requirements traceability

| Requirement | Where it is met |
|---|---|
| FR1 choose language and scope | `--lang`, `--category code\|deps\|all`, `--tools`, `--include-tests` |
| FR2 unified report | One ranked, deduplicated finding list across all tools and categories, in five formats |
| FR3 exportable, opens in Excel | `findings.csv` (UTF-8 BOM, Excel dialect), plus SARIF and JSON for tooling |
| FR4 CVE/CWE identification | CWE on every code finding; CVE/GHSA for dependencies; OWASP Top 10 category on all |
| FR5 regression tests | `generated-tests/` JUnit 5 tests; `verify` confirms remediation |
| FR6 initiate scan and display results | `secpipe scan`: terminal summary, HTML dashboard |
| NFR1 simple setup | JDK only; Maven wrapper; `install.sh`; `doctor`; first scan is one command with no keys |
| NFR2 performance | Per-stage timings in the terminal and reports. The sample scans in about 1–2 s |
| NFR3 clear errors | Every error states the problem and a hint; exit code 2; `-v` for stack traces |
| NFR4 extensibility | `ScannerAdapter` + `ToolRegistry`, `JavaRule`, `ReportWriter`, bundled JSON catalogs |

## Not in the MVP (planned)

- GitHub Action wrapper (the SARIF output and exit codes are already CI-ready)
- More analyzers: SpotBugs/FindSecBugs, CodeQL, Joern (inter-procedural data flow), OWASP ZAP (dynamic testing)
- Inter-procedural taint tracking, and more languages behind `--lang`
- Hosted or multi-project dashboard
