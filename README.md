## What is aws-access-graph?
Determining who has access to what in Amazon Web Services is a hard problem to
solve.  Users might have several methods to obtain an authorization to perform
an action: through an IAM user and policies attached to it, by virtue of
membership in a group and policies attached to it, and by roles they may be
able to assume, sometimes successively, either directly via IAM users or
through a single sign-on interface.

This tool reviews AWS IAM constructs (users, groups, roles, and policies) as
well as Okta Identity Engine workplace identity constructs (users, groups) to
help identify what users have access to a given service.  A graph of these
constructs, where the entities are nodes, and relationships are edges is built
in memory and used to output a text report.  Optionally, a DGML or Graphviz
compatable DOT file can be output to allow visual inspection of these
relationships.

## Example usage
Presuming you are using a solution like aws-mfa or aws-vault to set AWS credentials in
environment variables, the use of the binary could look like this to identify what
users have access to AWS Glue:

```
aws-access-graph glue --okta-base-url example.okta.com --okta-api-token "00IciYEXAMPLE..."
```

The standard error (Terminal window output) would look similar to:
```
aws-access-graph  Copyright (C) 2023  Sean McElroy
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; see the LICENSE.txt file for details.

Getting STS client... [✓]
Enumerating Account Authorization Details... Getting IAM client... [✓]
[✓] 12 groups, 298 policies, 232 roles, 74 users read from AWS API.
[✓] 1 SAML providers read from AWS API.
Getting Okta group API client... [✓] 197 groups read from Okta API.
Getting Okta user API client... [✓] 217 users read from Okta API.
[✓] 55 AWS-related groups and 636 group members read from Okta API.
Analyzing managed policy contents... 
Analyzing managed policy contents... [✓] (count=298)
Analyzing assume role policy document contents... 
Analyzing assume policy document contents... [✓] (count=232)

Done.
```

Resulting from this is a cache directory (default is ~/db) and an
output directory (default is ~/output).  Within the output directory,
a report file named authorization-paths.txt is created, which would
contain contents similar to:

```
Report of accesses to AWS Glue generated on 2023-02-26T00:29:38.0625650Z
glue: ID:ksmith
	path: ID:ksmith->OktaUser:ksmith@example.com->OktaGroup:aws_123456789012_DataAnalyst->AwsIamRole:DataAnalyst->AwsIamPolicy:DataAnalystAthenaGlueS3->glue
	path: ID:ksmith->OktaUser:ksmith@example.com->OktaGroup:aws_123456789012_DataEngineer->AwsIamRole:DataEngineer->AwsIamPolicy:ExternalEngineerConsoleIDP->glue
	path: ID:ksmith->OktaUser:ksmith@example.com->OktaGroup:aws_123456789012_DataAnalyst->AwsIamRole:DataAnalyst->AwsIamPolicy:DataAnalystConsoleIDP->glue
	path: ID:ksmith->OktaUser:ksmith@example.com->OktaGroup:aws_123456789012_DataAnalyst->AwsIamRole:DataAnalyst->AwsIamPolicy:ReadOnlyAccess->glue
	path: ID:ksmith->OktaUser:ksmith@example.com->OktaGroup:aws_123456789012_DataEngineer->AwsIamRole:DataEngineer->AwsIamPolicy:ReadOnlyAccess->glue
glue: ID:jdoe
	path: ID:jdoe->OktaUser:jdoe@example.com->OktaGroup:aws_123456789012_DataAnalyst->AwsIamRole:DataAnalyst->AwsIamPolicy:DataAnalystAthenaGlueS3->glue
	path: ID:jdoe->OktaUser:jdoe@example.com->OktaGroup:aws_123456789012_DataAnalyst->AwsIamRole:DataAnalyst->AwsIamPolicy:DataAnalystConsoleIDP->glue
	path: ID:jdoe->OktaUser:jdoe@example.com->OktaGroup:aws_123456789012_DataAnalyst->AwsIamRole:DataAnalyst->AwsIamPolicy:ReadOnlyAccess->glue
```

In the above output, IAM and Okta users are grouped under the same "ID",
and all the paths that link the ID to the AWS service (glue in this example)
are spelled out.

## Command line arguments
The following is an output of the help screen displaying command line
arguments:

```
AWS Access Graph 1.0.3
Copyright (C) 2023 Sean McElroy.  All rights reserved.

  --aws-access-key-id     If specified, the AWS Acccess Key ID to authenticate to the AWS
                          API.  If this is not specified but a value is present in the
                          environment variable AWS_ACCESS_KEY_ID, that value will be used
                          instead.  If that is not specified either, cached AWS policies
                          will be ignored, and this will be read programmatically using STS
                          get-caller-identity from the supplied credentials.  This value
                          usually begins with AKIA or ASIA

  --aws-secret-key        If specified, the AWS Secret Access Key to authenticate to the 
                          AWS API.  If this is not specified but a value is present in the
                          environment variable AWS_SECRET_ACCESS_KEY, that value will be
                          used instead.  If that is not specified either, cached AWS 
                          policies will be ignored, and this will be read programmatically
                          using STS get-caller-identity from the supplied credentials.

  --aws-session-token     If specified, the AWS Session Token to authenticate to the AWS
                          API.  If this is not specified but a value is present in the
                          environment variable AWS_SESSION_TOKEN, that value will be used
                          instead.  This is only relevant when a temporary session token is
                          used instead of a static IAM access key.

  --aws-account-id        If specified, the account number of the AWS account to analyze.  
                          If this is not specified but a value is present in the environment
                          variable AWS_ACCOUNT_ID, that value will be used instead.  If that
                          is not specified either, cached AWS policies will be ignored, and
                          this will be read programmatically using STS get-caller-identity
                          from the supplied credentials.

  --okta-base-url         If specified, the URL of the Okta instance to analyze, such as
                          example.okta.com.  If this is not specified but a value is present
                          in the environment variable OKTA_BASE_URL, that value will be used
                          instead.

  --okta-api-token        If specified, the API token of the Okta instance to analyze.  If 
                          this is not specified but a value is present in the environment
                          variable OKTA_API_TOKEN, that value will be used instead.

  -d, --dgml              Additionally output a DGML graph.

  -g, --graphviz          (Default: false) Additionally output a Graphviz DOT graph.

  --refresh               If specified, fresh data will be retrieved from all possible APIs.

  --refresh-aws           If specified, fresh data will be retrieved from the AWS API.

  --refresh-okta          If specified, fresh data will be retrieved from the Okta API.

  --no-files              If specified, no files will be written.  All API accesses are not
                          cached and all results are sent to standard output or standard
                          error only.

  --no-identity           If specified, graphs will not include individual principals, and
                           will terminate at the group or role level.  In complex graphs,
                          this can improve readibility of DGML or DOT files.

  --no-prune              If specified, nodes for services that are not the AwsServicePrefix
                          or that are not part of a direct service-to-identity path are
                          included on any output graphs.

  -v, --verbose           Produce verbose logs to standard output.

  --help                  Display this help screen.

  --version               Display version information.

  Service (pos. 0)        (Default: ec2) AWS service prefix for which to analyze authorizations.

  DB Path (pos. 1)        (Default: ./db) Path to cache API results for offline processing.

  Output Path (pos. 2)    (Default: ./output) Path to cache API results for offline processing.
```

## Caveats
This program does not yet handle NotAction and NotResource AWS IAM policy complications.
It also does not address IAM policy condition statements that may qualify authorization.
For these reasons, the output may have some false positives that indicate access is
granted to a service when a more complex policy actually does not provide for it.

## Licensing
This software is dual licensed under the terms of the GNU Affero General Public License
for non-commerical use.  Any commercial use or use of this software or any portion of it
in commercial offerings requires a separate proprietary license fom the author.

## Authors
To contact the author, email Sean McElroy at me@seanmcelroy.com.