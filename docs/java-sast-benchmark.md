# Java SAST rule benchmarking

This document records how `socket_basics/rules/java.yml` is measured and what the
current numbers are. It exists so the next person changing a Java rule can tell
whether they improved it or just moved the noise around.

## Why

A customer SAST evaluation reported roughly 90% false positives from our Java
rules, and compared us unfavourably to CodeQL. Reproducing that on real code
confirmed it: on six mature, heavily reviewed open source Java projects
(~17,400 Java files) the rule set emitted **1,631 findings**, and a hand
adjudicated random sample of 40 of them contained **zero true positives**.

## Corpora

Two corpora, because they answer different questions.

| Corpus | What it answers | Source |
|---|---|---|
| OWASP Benchmark v1.2 | Precision and recall against ground truth | `github.com/OWASP-Benchmark/BenchmarkJava` |
| Mature OSS Java projects | How much noise a real user has to triage | guava, netty, spring-framework, commons-lang, commons-io, spring-petclinic |
| WebGoat | Whether we still catch deliberately planted vulnerabilities | `github.com/WebGoat/WebGoat` |

OWASP Benchmark ships 2,740 annotated servlets (1,415 real vulnerabilities,
1,325 deliberate non-vulnerabilities) with an `expectedresults-1.2.csv` giving
the category, CWE, and whether each case is genuinely vulnerable. It is the
standard scoring corpus for Java SAST.

The mature-OSS corpus is the honest proxy for customer experience. These
libraries are not web applications and contain essentially no reachable
instances of these vulnerability classes, so nearly every finding is noise.
Alert volume there is the number that maps to triage burden.

## Running it

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git

opengrep --json --dataflow-traces --quiet -a --no-git-ignore \
  --config socket_basics/rules/java.yml \
  --output results.json \
  BenchmarkJava/src/main/java

python3 scripts/score_owasp_benchmark.py results.json \
  BenchmarkJava/expectedresults-1.2.csv
```

The scorer reports per-category precision, recall, false positive rate and the
OWASP Benchmark score (`TPR - FPR`), plus per-rule TP/FP counts so you can see
which rule is responsible for a regression.

## Results

Measured with opengrep 1.25.0.

### OWASP Benchmark v1.2 (ground truth)

| | Before | After |
|---|---|---|
| Precision | 64.5% | **76.5%** |
| Recall | 12.4% | **63.4%** |
| False positive rate | 7.3% | 20.8% |
| Benchmark score (TPR - FPR) | 5.1 | **42.6** |
| True positives found | 176 | **897** |

Per category, after the change:

| Category | Precision | Recall |
|---|---|---|
| securecookie | 100.0% | 100.0% |
| weakrand | 100.0% | 91.7% |
| crypto | 100.0% | 74.6% |
| hash | 100.0% | 69.0% |
| xpathi | 60.0% | 80.0% |
| ldapi | 58.3% | 77.8% |
| xss | 67.4% | 70.7% |
| pathtraver | 56.1% | 69.2% |
| cmdi | 63.6% | 44.4% |
| sqli | 64.9% | 44.1% |

The headline false positive rate rises because the rule set now detects seven
categories it previously scored zero on. Precision, which is the share of
emitted findings that are real, is the comparable number and it improved.

### Mature open source Java projects (triage burden)

| | Before | After | Change |
|---|---|---|---|
| Total findings | 1,631 | 130 | **-92%** |
| Unique findings, mature libraries only | 1,536 | 85 | **-94.5%** |

Three rules produced 74% of the original noise: `java-empty-catch-block` (645),
`java-reflection-injection` (296) and `java-system-out-usage` (263). All three
now emit zero findings on the mature-library corpus.

### WebGoat (deliberately vulnerable)

87 findings before, 45 after. The removed findings were lint noise
(`java-system-out-usage` 26, `java-hardcoded-ip` 5, `java-empty-catch-block` 4)
plus three `java-reflection-injection` matches on factory `newInstance()` calls
and a JDK dynamic proxy. The security findings, including the Zip Slip in
`ProfileZipSlip`, the default credentials in `DefaultCredentialsTask`, and the
weak PRNG in `PasswordResetLink`, are still reported.

## Known limits

**OWASP Benchmark's designated false positives are adversarial toward
pattern-based engines.** A large share of them are unreachable-branch traps:

```java
String guess = "ABC";
char switchTarget = guess.charAt(1);   // always 'B', the safe branch
switch (switchTarget) {
  case 'A': bar = param; break;        // tainted, but dead code
  case 'B': bar = "bob"; break;        // always taken
}
```

Resolving these requires constant propagation plus path sensitivity. opengrep's
taint analysis is path insensitive, so it reports the dead tainted branch. This
is the structural difference behind the "Semgrep matches patterns, CodeQL traces
paths" comparison, and it caps achievable precision on `sqli`, `cmdi` and
`pathtraver` regardless of how the rules are written. Do not read the remaining
FPs in those categories as fixable rule defects without checking the test case
first.

**Remaining noise not addressed here.** On the mature-library corpus these rules
were untouched by this change and are still the largest remaining sources:

| Rule | Findings | Cause |
|---|---|---|
| `java-template-injection` | 20 | Matches any `.process(...)` call |
| `java-xxe-vulnerability` | 14 | Matches `DocumentBuilderFactory.newInstance()` unconditionally, ignoring whether secure features are set |
| `java-unsafe-deserialization` | 14 | Library serialization helpers that accept a caller-supplied `ObjectInputStream` |
| `java-jndi-injection` | 8 | Matches any `.lookup(...)` call |
| `java-sql-injection` | 4 | `$STMT.execute(...)` and `$TEMPLATE.query(...)` sinks match any method of those names |

`trustbound` (CWE-501) has no rule at all; OWASP Benchmark scores 126 cases for it.
