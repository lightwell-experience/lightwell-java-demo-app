# lightwell-java-demo-app

A demo application that pairs with the Lightwell demo repositories to show how
**Red Hat Lightwell** can remediate the dependencies of a Java (Maven) project.

The application, "Help, I'm Vulnerable!", is a small Spring Boot 2.6.6 service.
Its dependencies are pinned on purpose to versions with known CVEs. Lightwell
publishes rebuilt versions of these artifacts (for example `6.0.3.rhlw-00001`)
that backport the security fixes but keep the same upstream version line. You
get a fix without a disruptive major or minor upgrade.

> ⚠️ **Do not deploy this application in production.** It intentionally ships
> vulnerable dependencies for demonstration purposes.

## How the demo works

1. **Baseline:** `pom.xml` declares vulnerable upstream versions (Woodstox
   6.0.3, org.json 20220320, json-path 2.8.0, Spring Framework 5.3.18 via Spring
   Boot 2.6.6, and others).
2. **Resolution:** Maven is configured (see [`.mvn`](#maven-configuration-mvn))
   to resolve artifacts from the Lightwell demo repositories first, so the
   `rhlw` builds can be found.
3. **Remediation PRs:** Renovate (see [Renovate configuration](#renovate-configuration))
   checks the Lightwell remediated repository and opens pull requests that move
   each direct dependency to its Lightwell-remediated version.
4. **Transitive remediations:** Spring Framework is not declared in `pom.xml`.
   A second workflow pins the Lightwell rebuilds of those transitive
   dependencies in a BOM. See [Transitive dependencies](#transitive-dependencies).
5. **Verification:** The build generates a CycloneDX SBOM. You can upload it to
   Red Hat Trusted Profile Analyzer (TPA) to compare the vulnerability posture
   before and after remediation.

## Maven configuration (`.mvn`)

The `.mvn` directory is what lets Maven resolve the Lightwell artifacts. Any
`mvn` command run from the project root picks it up automatically. No extra
flags or changes to `~/.m2/settings.xml` are needed.

### `.mvn/maven.config`

```
-s
.mvn/settings.xml
```

Maven (3.3.1+) reads `.mvn/maven.config` and adds its contents to every command
line. This one passes `-s .mvn/settings.xml`, so Maven uses the project-local
settings file **instead of** your user settings (`~/.m2/settings.xml`).

### `.mvn/settings.xml`

This file defines an always-active profile, `lightwell-remediated`, that adds
two repositories. Maven checks them in this order:

| Order | Repository ID          | URL                                                                                  |
|-------|------------------------|--------------------------------------------------------------------------------------|
| 1     | `lightwell-remediated` | `https://packages.redhat.com/lightwell/public-lightwell-demo/java/remediated/`       |
| 2     | `lightwell-validated`  | `https://packages.redhat.com/lightwell/public-lightwell-demo/java/validated/`        |
| 3     | Maven Central          | Added implicitly by the Maven super POM, always last                                 |

- **remediated** hosts the Lightwell-rebuilt artifacts that carry backported
  CVE fixes (`*.rhlw-NNNNN` versions).
- **validated** hosts upstream artifacts that Lightwell has validated.
- Snapshots are disabled for both. Only releases are resolved.

These are the *public demo* repositories, so no credentials are required.

Because the `Containerfile` copies `.mvn` and `lightwell-pins-repo` into the
build stage, container builds resolve dependencies the same way local builds do.

## Renovate configuration

Renovate is what actually proposes the remediations. Its configuration is in
[`renovate.json`](renovate.json):

```json
{
  "extends": [
    "config:recommended",
    "github>lightwell-experience/renovate-config:java-remediated#1.0.2"
  ],
  "packageRules": [
    {
      "description": "Use the public Lightwell demo repository (no auth required) instead of the default Lightwell registry",
      "matchManagers": ["custom.regex"],
      "matchDatasources": ["maven"],
      "registryUrls": [
        "https://packages.redhat.com/lightwell/public-lightwell-demo/java/remediated/"
      ]
    },
    {
      "description": "The transitive pin BOM is updated by the transitive-pins workflow",
      "matchManagers": ["custom.regex"],
      "matchPackageNames": ["com.lightwell:rhlw-pins"],
      "enabled": false
    }
  ]
}
```

- **`config:recommended`**: Renovate's standard baseline preset.
- **`github>lightwell-experience/renovate-config:java-remediated#1.0.2`**: The
  shared Lightwell preset for Java projects, pinned to tag `1.0.2`. It teaches
  Renovate how to find and propose Lightwell-remediated (`rhlw`) versions of
  Maven dependencies.
- **`packageRules`**: Overrides the registry the preset's `custom.regex`
  manager uses for Maven lookups. It points to the **public demo** remediated
  repository instead of the default Lightwell registry, so the demo works
  without authentication. This is the same URL used in `.mvn/settings.xml`.

### Transitive dependencies

The preset's `custom.regex` manager only sees dependencies written in
`pom.xml` with a literal `<groupId>`/`<artifactId>`/`<version>`. Renovate's
built-in Maven manager is disabled. Transitive dependencies, such as the Spring
Framework modules that `spring-boot-starter-parent` manages, are invisible to
Renovate, so it never proposes their rebuilds.

To fix that, `pom.xml` pins the affected transitive dependencies in
`<dependencyManagement>` at their **upstream** version:

| Dependency                              | Pinned at | Rebuild Renovate proposes |
|-----------------------------------------|-----------|---------------------------|
| `org.springframework:spring-core`       | `5.3.18`  | `5.3.18.rhlw-00010`       |
| `org.springframework:spring-expression` | `5.3.18`  | `5.3.18.rhlw-00010`       |
| `org.springframework:spring-webmvc`     | `5.3.18`  | `5.3.18.rhlw-00010`       |

The pins match what Boot 2.6.6 already resolves, so they don't change the
build. They only give Renovate something to match, so it opens remediation PRs
for these artifacts as it does for direct dependencies.

These three were found with
[`scripts/pin-transitives.mjs`](https://github.com/lightwell-experience/renovate-config/blob/main/scripts/pin-transitives.mjs)
from the `lightwell-experience/renovate-config` repo. It's the approach
described in
[Manage Java transitive dependencies with Lightwell rebuilds](https://developers.redhat.com/articles/2026/11/03/manage-java-transitive-dependencies-lightwell-rebuilds).
The script resolves the full Maven dependency tree, runs a local Renovate
dry-run lookup against it, and reports every dependency, direct or transitive,
that has an `rhlw` rebuild. Of 53 resolved dependencies, these were the only
transitive ones with rebuilds. Run it from the project root:

```bash
git clone https://github.com/lightwell-experience/renovate-config /tmp/renovate-config
(cd /tmp/renovate-config && npm install --no-save renovate@42)

node /tmp/renovate-config/scripts/pin-transitives.mjs \
  --mvn "mvn -B -Dstyle.color=never org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree -DoutputType=json -DoutputFile=/tmp/dependency-tree.json" \
  --renovate 'LOG_FORMAT=json /tmp/renovate-config/node_modules/.bin/renovate --platform=local --onboarding=false --dry-run=lookup > "$RENOVATE_LOG_FILE"'
```

The extra flags work around three issues:

- **`--mvn`:** Spring Boot 2.6.6 pins `maven-dependency-plugin` 3.2.0, which
  can't write a JSON tree (that needs 3.7.0+). The flag calls 3.8.1 explicitly.
- **`renovate@42`:** Renovate 43+ requires Node 24. Version 42 still runs on
  Node 22. On Node 24 you can use the default install instead.
- **`--renovate`:** Renovate 42 ignores `RENOVATE_LOG_FILE`, so the command
  writes JSON logs to stdout and redirects them into the file the script reads.

> **When upgrading Spring Boot**, update these pins to the new Boot version's
> Spring Framework version, then rerun the script. Otherwise
> `<dependencyManagement>` keeps forcing Spring Framework 5.3.18 under the
> newer Boot. Rerun the script from time to time anyway, to catch transitive
> dependencies that get new rebuilds later.

### Running Renovate

Renovate runs as a GitHub Action, defined in
[`.github/workflows/renovate.yml`](.github/workflows/renovate.yml). It runs:

- daily at 06:00 UTC, and
- on demand through **Actions → Renovate → Run workflow** (you can pick an
  `info` or `debug` log level).

The workflow sets `RENOVATE_REQUIRE_CONFIG: required`, so `renovate.json` must
be present, and it disables onboarding. It uses the `RENOVATE_TOKEN` secret if
set and otherwise falls back to `GITHUB_TOKEN`. Use a PAT or GitHub App token
in `RENOVATE_TOKEN` if you want Renovate's PRs to trigger other workflows.

## Transitive dependencies

Renovate rewrites `<version>` tags in `pom.xml`. Spring Framework has no
version tag there. `spring-boot-starter-web` and `spring-boot-starter-security`
bring in `spring-core`, `spring-webmvc`, and `spring-expression` at 5.3.18.
The public remediated repository publishes `5.3.18.rhlw-00010` for each.

`pom.xml` imports `com.lightwell:rhlw-pins` from `lightwell-pins-repo/`. The
committed BOM is `0.0.1` with an empty `dependencyManagement`, so those
libraries stay on the Boot versions until the update workflow runs. Direct
dependencies keep the version in `pom.xml`.

[`.github/workflows/transitive-pins.yml`](.github/workflows/transitive-pins.yml)
runs daily at 07:00 UTC and from **Actions → Transitive pins → Run workflow**.
It checks out `lightwell-experience/renovate-config` at `main` and runs
`scripts/pin-transitives.mjs --write` on
`lightwell-pins-repo/com/lightwell/rhlw-pins/latest/rhlw-pins-latest.pom`.
That file keeps the current BOM version. The script rewrites it and does not
edit `pom.xml`. The workflow copies it to
`lightwell-pins-repo/com/lightwell/rhlw-pins/<version>/` and sets the
`rhlw-pins` import to match. Numbered versions already in the repo are left
as they are. The workflow opens a pull request when those files change.

## Building and running

### Locally

Requires Java 17 and Maven 3.3.1 or later.

```bash
mvn clean package
java -jar target/help-im-vulnerable-1.0.0.jar
```

Open http://localhost:8080 to see a dashboard that lists each vulnerable
dependency, its CVEs, the Lightwell fix version (if one exists), and whether
the library loaded. The same data is available as JSON at
http://localhost:8080/api/status.

### Container

```bash
podman build -f Containerfile -t help-im-vulnerable .
podman run --rm -p 8080:8080 help-im-vulnerable
```

## SBOM generation

The `cyclonedx-maven-plugin` writes a CycloneDX 1.6 SBOM to `target/bom.json`
during `package`.

To get a complete SBOM that covers both the Java dependencies and the container
OS packages, run:

```bash
./generate-sbom.sh [image-name] [sbom-name] [sbom-version] [output-file]
```

This script requires `podman`, `syft`, and `python3`. It builds the image,
extracts the Maven SBOM, generates a container SBOM with syft, and merges the
two with `merge-sboms.py`. Maven metadata takes priority for Java components.
The result is written to `sbom.json`, which you can upload to TPA.

## Repository layout

| Path                                    | Purpose                                                |
|-----------------------------------------|--------------------------------------------------------|
| `pom.xml`                               | Maven build with intentionally vulnerable dependencies |
| `lightwell-pins-repo/`                  | `rhlw-pins` BOM. `latest/` is rewritten; Maven imports a numbered copy |
| `.mvn/`                                 | Project-local Maven config pointing to Lightwell repos |
| `renovate.json`                         | Renovate config using the Lightwell Java preset        |
| `.github/workflows/renovate.yml`        | Scheduled and manual Renovate runs                     |
| `.github/workflows/transitive-pins.yml` | Scheduled and manual transitive pin updates            |
| `Containerfile`                         | Multi-stage UBI9 / OpenJDK 17 image build              |
| `generate-sbom.sh`                      | Builds the image and produces a merged SBOM            |
| `merge-sboms.py`                        | Merges the Maven and syft CycloneDX SBOMs              |
| `src/`                                  | Spring Boot application source                         |
