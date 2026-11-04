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
   each vulnerable dependency to its Lightwell-remediated version.
4. **Verification:** The build generates a CycloneDX SBOM. You can upload it to
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

Because the `Containerfile` copies `.mvn` into the build stage
(`COPY .mvn ./.mvn`), container builds resolve dependencies the same way local
builds do.

## Renovate configuration

Renovate is what actually proposes the remediations. Its configuration is in
[`renovate.json`](renovate.json):

```json
{
  "extends": [
    "config:recommended",
    "github>lightwell-experience/renovate-config:java-remediated#1.0.0"
  ],
  "packageRules": [
    {
      "description": "Use the public Lightwell demo repository (no auth required) instead of the default Lightwell registry",
      "matchManagers": ["custom.regex"],
      "matchDatasources": ["maven"],
      "registryUrls": [
        "https://packages.redhat.com/lightwell/public-lightwell-demo/java/remediated/"
      ]
    }
  ]
}
```

- **`config:recommended`**: Renovate's standard baseline preset.
- **`github>lightwell-experience/renovate-config:java-remediated#1.0.0`**: The
  shared Lightwell preset for Java projects, pinned to tag `1.0.0`. It teaches
  Renovate how to find and propose Lightwell-remediated (`rhlw`) versions of
  Maven dependencies.
- **`packageRules`**: Overrides the registry the preset's `custom.regex`
  manager uses for Maven lookups. It points to the **public demo** remediated
  repository instead of the default Lightwell registry, so the demo works
  without authentication. This is the same URL used in `.mvn/settings.xml`.

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

| Path                              | Purpose                                                    |
|-----------------------------------|------------------------------------------------------------|
| `pom.xml`                         | Maven build with intentionally vulnerable dependencies     |
| `.mvn/`                           | Project-local Maven config pointing to Lightwell repos     |
| `renovate.json`                   | Renovate config using the Lightwell Java preset            |
| `.github/workflows/renovate.yml`  | Scheduled and manual Renovate runs                         |
| `Containerfile`                   | Multi-stage UBI9 / OpenJDK 17 image build                  |
| `generate-sbom.sh`                | Builds the image and produces a merged SBOM                |
| `merge-sboms.py`                  | Merges the Maven and syft CycloneDX SBOMs                  |
| `src/`                            | Spring Boot application source                             |
