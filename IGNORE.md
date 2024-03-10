# IGNORE

This feature allows certain paths that would otherwise be written into output files to be omitted from them if a matching condition is documented in the IGNORE.csv file.  By default, this file is found in ./conf/IGNORE.csv, although the location of configuration files can be modified via a command line argument from the default location of ./conf

The effect of this file could render an authorization text report line such as:

```path: ID:jdoe->IdentityStoreUser:jdoe@example.com->IdentityStoreGroup:Engineers->AwsPermissionSet:Engineers->AwsInlinePolicy:Engineers/AllowEc2Management->ec2(WRITE)```

To be omitted completely from authorization text files if the IGNORE.csv file contains either a record like the examples in the following sections.

NOTE: This feature only affects authorization text file reports.  It does not omit any information in DGML or Graphviz file outputs, if enabled as a command line argument.

## Example 1
```
Identity,Service
ID:jdoe,ec2(WRITE)
```
... would ignore ec2 write permissions for identtiy 'jdoe', whether that identity was graphed through an Okta user, an AWS IAM User, or an AWS IAM Identity Center 'user' in Identity Store.

## Example 2
```
Identity,Service
IdentityStoreUser:jdoe@example.com,ec2(WRITE)
```
... would ignore ec2 write authorizations for anyone assigned to a user with the username jdoe@example.com in AWS Identity Store.

## Example 3
```
Identity,Service
IdentityStoreGroup:Engineers,ec2(WRITE)
```
... would ignore ec2 write authorizations for anyone assigned to the Engineers group in AWS Identity Store.

## Example 4
Alternatively, an authorization text report that contains a line like `path: ID:jdoe->AwsIamUser:jdoe->AwsIamGroup:Auditors->AwsIamPolicy:ReadOnlyAccess->ec2` could be omitted completely with either `ID:jdoe,ec2` or with `AwsIamUser:jdoe,ec2` in IGNORE.csv, after the header.

In all cases, the ignoring algorithm looks for any identity part of the graph (ID, IdentityStoreUser, IdentityStoreGroup, AwsIamUser, or AWSIamGroup) connecting an identity to a target service matching the first column of the CSV record (such as ID:jdoe) and then the final target service matching the second column.  Because of this design, specifying 'ec2' for an identity in the second column of the IGNORE.csv will ignore findings containing target services of 'ec2' or 'ec2(WRITE)'.  However, specifying 'ec2(WRITE)' in the second column of IGNORE.csv will not ignore ec2 findings, since a full string match is tested.

If IGNORE.csv is not found, no lines are ignored.  If any lines are ignored, a count of ignored lines is output to standard error.