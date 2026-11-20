### Added Features

- Add support for scanning single purl from the CLI [[#2225](https://github.com/anchore/grype/issues/2225) [#2223](https://github.com/anchore/grype/pull/2223) @wagoodman]

### Bug Fixes

- Docker reports 0 vulnerabilities.  Same file reports many vulnerabilites when ran directly on linux server [[#2235](https://github.com/anchore/grype/issues/2235)]
- Flaky checks on STDIN for purl provider [[#2192](https://github.com/anchore/grype/issues/2192) [#2223](https://github.com/anchore/grype/pull/2223) @wagoodman]
- Missing alpine patch version yields inaccurate results [[#2222](https://github.com/anchore/grype/issues/2222) [#2226](https://github.com/anchore/grype/pull/2226) @wagoodman]

### Additional Changes

- update Syft to v1.16.0 [[#2237](https://github.com/anchore/grype/pull/2237) @anchore-actions-token-generator]

**[(Full Changelog)](https://github.com/anchore/grype/compare/v0.83.0...v0.84.0)**
