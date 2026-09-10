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

Pin both the engine and the corpus, or the numbers below will not reproduce.

- **Engine.** Measured with **opengrep 1.26.0**, the release the images pin
  (`OPENGREP_VERSION` in `Dockerfile` and `Dockerfile.heavy`). Rule behaviour
  was identical on 1.19.0, 1.25.0 and 1.26.0 everywhere it was checked, but
  re-measure if you change the pin.
- **Corpus.** BenchmarkJava at commit
  [`51f0a7c`](https://github.com/OWASP-Benchmark/BenchmarkJava/commit/51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661)
  (2026-08-31). A `--depth 1` clone of `main` moves, and both the test cases and
  the `expectedresults` CSV have changed between Benchmark releases.

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
git -C BenchmarkJava checkout 51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661

opengrep --json --dataflow-traces --quiet --no-git-ignore \
  --config socket_basics/rules/java.yml \
  --output results.json \
  BenchmarkJava/src/main/java

python3 scripts/score_owasp_benchmark.py results.json \
  BenchmarkJava/expectedresults-1.2.csv
```

The scorer reports per-category precision, recall, false positive rate and the
OWASP Benchmark score (`TPR - FPR`), plus per-rule TP/FP counts so you can see
which rule is responsible for a regression.

## Regression tests

The full corpora are not needed to catch the regressions that are easiest to
reintroduce. `tests/fixtures/opengrep/java` holds one small Java file per rule
area, annotated `// ruleid: <rule>` for a line that must be reported and
`// ok: <rule>` for one that must not. `tests/test_java_opengrep_rules.py`
scans them and diffs against the annotations:

```bash
pytest tests/test_java_opengrep_rules.py
```

Locally the tests skip when `opengrep` is not on `PATH`. CI installs the
release pinned in `Dockerfile` and sets `SOCKET_BASICS_REQUIRE_OPENGREP=1`, so
there a missing engine fails the job instead of skipping the module. Add a case
to the relevant fixture whenever you change a rule; the substring,
qualified-name and containment-check bugs found in review are all covered there
now.

Three behaviours worth knowing when editing these:

- `metavariable-regex` **anchors at the start** of the metavariable text, so
  every alternation branch needs its own leading `.*`.
- Prefer scoped `(?i:...)` groups over a leading global `(?i)`. A global flag
  also lowercases the deliberately case-sensitive camelCase branches, which is
  how `pivot`, `divisor`, `spinner` and `monkey` were matching `iv`, `pin` and
  `key`.
- opengrep's default ignore list skips any path under a `tests/` directory, and
  on some releases (1.19.0) that applies even to explicitly listed files. The
  harness therefore scans a temporary copy of the fixtures and asserts that
  every fixture was actually scanned, so an ignored file fails loudly instead
  of passing every negative annotation by scanning nothing.

## Results

Measured with opengrep 1.26.0.

Scan time on BenchmarkJava went from 6s to 11s, roughly +70%. The extra cost is
the taint-mode conversions and the wider sink lists. It is small in absolute
terms on a 2,766 file corpus, but it is not free, and it is worth re-checking if
more rules move to taint mode. Run the corpora sequentially: seven concurrent
opengrep processes on one machine thrash badly.

### OWASP Benchmark v1.2 (ground truth)

Both columns are produced by the current `scripts/score_owasp_benchmark.py`,
so they share a denominator. An earlier revision of this table quoted a Before
column from a scorer that still mapped the non-existent
`java-trust-boundary-violation` rule, which counted Benchmark's 126
`trustbound` cases against recall on the Before side only.

| | Before | After |
|---|---|---|
| Precision | 64.5% | **76.7%** |
| Recall | 13.2% | **71.3%** |
| False positive rate | 7.6% | 22.5% |
| Benchmark score (TPR - FPR) | 5.6 | **48.9** |
| True positives found | 176 | **950** |

Per category, after the change:

| Category | Precision | Recall |
|---|---|---|
| securecookie | 100.0% | 100.0% |
| weakrand | 100.0% | 100.0% |
| crypto | 100.0% | 74.6% |
| hash | 100.0% | 69.0% |
| xpathi | 60.0% | 80.0% |
| ldapi | 58.3% | 77.8% |
| xss | 67.4% | 70.7% |
| pathtraver | 56.1% | 69.2% |
| sqli | 66.8% | 57.0% |
| cmdi | 63.6% | 44.4% |

**Cross-category findings are not counted.** Following the OWASP method, the
scorer only credits a finding when the rule's category matches the CWE the test
case targets; a finding of a different class in that file is discarded rather
than counted as a false positive. That is worth stating because it hid a real
bug. Before this change, 93 discarded pairs were `java-sql-injection` firing on
`hash` test cases, because the untyped `$TEMPLATE.update(...)` sink matched
`MessageDigest.update(input)`. Subtracting the crypto receivers fixed it and
raised `sqli` recall at the same time. 40 discarded pairs remain, all `java-xss`
on `sqli` and `xpathi` cases, where the test genuinely echoes the tainted value
into the response; those look like real findings the OWASP scoring model
discards. Counting all 40 as false positives would put overall precision at
74.3% rather than 76.7%.

Making the SQL string the only sink argument (so parameterized
`update("... = ?", input)` calls stop being reported) and adding
`prepareStatement()` as a sink moved `sqli` from 142 to 155 true positives at
slightly higher precision. Demoting the `File` and `Path` constructors from
sinks to propagators, with filesystem operations such as `exists()` as the
sinks instead, left `pathtraver` exactly where it was: 107 of Benchmark's 268
path traversal cases never open the file, they only probe it.

The headline false positive rate rises because the rule set now detects seven
categories it previously scored zero on. Precision, which is the share of
emitted findings that are real, is the comparable number and it improved.

### Mature open source Java projects (triage burden)

| | Before | After | Change |
|---|---|---|---|
| Total findings | 1,631 | 126 | **-92%** |
| Unique findings, mature libraries only | 1,536 | 83 | **-94.6%** |

Two caveats on these counts, both of which apply equally to the Before and
After columns:

- **Part of the reduction is scoping, not rule logic.** Several rules gained a
  `paths: exclude` block for test, benchmark and example directories. 429 of the
  1,631 baseline findings (26%) sit in paths that are now excluded, concentrated
  in `java-system-out-usage` (212 of its 263, mostly netty's `example` module),
  `java-insecure-random` (82 of 102) and `java-hardcoded-ip` (35 of 48). Those
  three rules would still be much quieter without the exclusions, but "zero
  findings" for them is scoping plus logic, not logic alone.
- **guava is counted twice.** The repository ships `guava/` and a near-identical
  `android/guava/` mirror, and both are scanned. Exactly half of guava's
  findings are mirror duplicates (245 of 490 before, 10 of 20 after), and the
  same applies to its share of the ~17,400 file count.

Three rules produced 74% of the original noise: `java-empty-catch-block` (645),
`java-reflection-injection` (296) and `java-system-out-usage` (263). All three
now emit zero findings on the mature-library corpus.

### WebGoat (deliberately vulnerable)

87 findings before, 43 after. The removed findings were lint noise
(`java-system-out-usage` 26, `java-hardcoded-ip` 5, `java-empty-catch-block` 4),
three `java-reflection-injection` matches on factory `newInstance()` calls and a
JDK dynamic proxy, and two `java-path-traversal` duplicates on `new File(...)`
constructors (one of them only ever passed to a log statement) now that the
filesystem operation rather than the constructor is the sink. The security
findings, including the Zip Slip in `ProfileZipSlip`, the default credentials in
`DefaultCredentialsTask`, and the weak PRNG in `PasswordResetLink`, are still
reported.

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

**Declared types are all the matcher sees.** A typed metavariable such as
`(Random $R)` matches on the *declared* type, so a `SecureRandom` assigned into
a `Random`-typed variable is still treated as a weak PRNG:

```java
Random rng = new SecureRandom();                       // declared Random
String token = Long.toString(rng.nextLong(), 36);      // reported
```

There is no clean pattern-level fix. Narrowing the source to
`new Random(...)` only would lose every case where the PRNG is held in a field,
which is the common real-world shape, so this is accepted as a known false
positive rather than traded for the recall.

**Comment exclusions are statement scoped.** `java-empty-catch-block` excludes
a catch block carrying an explanatory comment with `pattern-not-regex`, because
comments are not AST nodes. The regex is applied to the whole matched `try`
statement, so a comment in one catch clause suppresses an empty broad catch
beside it:

```java
try { work(); }
catch (IOException e) { // fine, fall through
} catch (Exception e) { }   // not reported
```

Anchoring the regex to the clause that binds the exception variable is not
expressible in a single rule. The same code without the comment on the first
clause is reported.

**Containment checks must be visible as one expression.** `java-path-traversal`
recognises `Path.startsWith`, `normalize().startsWith` and
`getCanonicalPath().startsWith` as containment when the check is written on the
variable that later reaches the sink, and the `File`/`Path` constructors are
propagators rather than sinks so the check gets a chance to run. The String
form, `String canon = f.getCanonicalPath(); if (!canon.startsWith(base))`, is
indistinguishable from a bypassable prefix blacklist such as
`name.startsWith("..")` and is not a sanitizer, so that spelling of the idiom is
still reported at the open.

**Ambiguous names in `java-insecure-random`.** The sink matches a security
value by name, and `key` is genuinely ambiguous in Java. `rememberMeKey` (a
Benchmark true positive) and `shardKey` or `cacheKey` (map keys, not secrets)
are the same shape, so the rule reports all of them. Narrowing `key` to compound
forms only, as `java-hardcoded-credentials` does, would drop `weakrand` recall
from 100%. The short words `iv`, `pin`, `otp`, `key` and `auth` are matched only
at a word boundary, so `pivot`, `divisor`, `spinner`, `monkey` and `author` are
not reported, but `keyIndex` and `ivLen` still are.

**`java-unsafe-deserialization` still reports library plumbing.** Guava's and
commons-lang's serialization helpers take a caller-supplied `ObjectInputStream`
and call `readObject()` on it, outside the `Serializable` contract methods the
rule excludes. Whether that is a finding depends on who calls the helper, which
is not visible to the rule.

**Remaining noise not addressed here.** On the mature-library corpus these rules
are the largest remaining sources:

| Rule | Findings | Cause |
|---|---|---|
| `java-template-injection` | 20 | Matches any `.process(...)` call |
| `java-xxe-vulnerability` | 14 | Matches `DocumentBuilderFactory.newInstance()` unconditionally, ignoring whether secure features are set |
| `java-unsafe-deserialization` | 24 | Library serialization helpers that accept a caller-supplied `ObjectInputStream`, plus Spring's `YamlProcessor`, whose restrictive `Constructor` and tag inspector are configured in a different method from the `loadAll()` call |
| `java-jndi-injection` | 8 | Matches any `.lookup(...)` call |
| `java-sql-injection` | 2 | `$STMT.execute(...)` still matches any method named `execute` with a tainted first argument. Two SpEL `ConstructorExecutor.execute()` matches dropped out once the SQL string became the only sink argument |
| `java-unvalidated-redirect` | 4 | All four are Spring's own `RedirectView`, which is the framework's redirect implementation |

Every one of these is the same defect class the change fixes elsewhere: an
untyped receiver on a common method name. The pattern to follow is a typed
metavariable plus a fully qualified variant, as in `java-ldap-injection`.

`trustbound` (CWE-501) has no rule at all; OWASP Benchmark scores 126 cases for
it, and `scripts/score_owasp_benchmark.py` deliberately omits the category so it
reads as unscored rather than as a rule at 0% recall.
