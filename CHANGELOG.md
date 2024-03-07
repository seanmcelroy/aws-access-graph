# Changelog

## 1.1.1 - 2024-03-06

### Changed

- (BUG) If no-identity is specified, provide group (but not user) data.  Previously this created an empty report

## 1.1.0 - 2023-12-11

### Added

- New command line argument --aws-profile allows specifying an AWS profile configured in the local environment
- Support for IAM Identity Center by calling a named profile instead of specifying --aws-access-key-id, --aws-secret-key, or --aws-session-token or requiring those values to be provided in the environment

### Changed

- If refresh-okta is specified and no Okta base URL is provided, quite with an error
- When running a refresh run over multiple AWS accounts, read Okta data at most one time
- Minor spelling corrections
- Authorization Path reports now list the accounts over which they were run in the header.
- Authorization Path reports now provide the AWS account ID for AWS resources when run over more than one account.

## 1.0.4 - 2023-07-05

### Changed

- Improved error handling if a missing trust policy was found during multi-account processing

## 1.0.3 - 2023-07-03

### Added

- Add auto-creation of DB path and OUTPUT path if they do not exist
- Improve error handling if no database files present when run without arguments

### Changed

- Remove printing of de-duplication stats if no dupes encountered
- Updated dependencies to latest versions