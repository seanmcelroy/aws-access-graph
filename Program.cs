/*
This file is part of aws-access-graph.

aws-access-graph is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.

aws-access-graph is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License along with
aws-access-graph. If not, see <https://www.gnu.org/licenses/>.
*/

using System.Diagnostics;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using AwsAccessGraph;
using AwsAccessGraph.DirectedGraphMarkupLanguage;
using AwsAccessGraph.Graphviz;
using CommandLine;
using static AwsAccessGraph.Constants;

internal class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.Error.WriteLine("aws-access-graph  Copyright (C) 2023  Sean McElroy");
        Console.Error.WriteLine("This program comes with ABSOLUTELY NO WARRANTY.");
        Console.Error.WriteLine("This is free software, and you are welcome to redistribute it");
        Console.Error.WriteLine("under certain conditions; see the LICENSE.txt file for details.");
        Console.Error.WriteLine();

        return await Parser.Default.ParseArguments<CommandLineOptions>(args)
        .MapResult(async (CommandLineOptions opts) =>
        {
            if (args.Length == 0 || string.IsNullOrWhiteSpace(args.Aggregate((c, n) => $"{c}{n}")))
            {
                Console.Error.WriteLine("No arguments supplied.  Use the --help argument for help.");
                return 0;
            }

            if (!opts.AwsServicePrefix.Contains(',') &&
                !Constants.AwsServicePolicyNames.ContainsKey(opts.AwsServicePrefix.ToLowerInvariant()))
            {
                Console.Error.WriteLine($"Service {opts.AwsServicePrefix} not specified.  Must be a valid AWS service prefix or a common-delimited list of valid service prefixes");
                return (int)ExitCodes.InvalidAwsServicePrefix;
            }

            var cts = new CancellationTokenSource();
            try
            {
                Console.CancelKeyPress += delegate
                {
                    cts.Cancel();
                };

                var dbPath = Path.Combine(Environment.CurrentDirectory, opts.DbPath);
                if (!Directory.Exists(dbPath))
                {
                    Console.Error.WriteLine($"Cannot find db directory in working path. Creating: {dbPath}");
                    Directory.CreateDirectory(dbPath);
                }

                var outputPath = Path.Combine(Environment.CurrentDirectory, opts.OutputPath);
                if (!Directory.Exists(outputPath))
                {
                    Console.Error.WriteLine($"Cannot find output directory in working path. Creating: {outputPath}");
                    Directory.CreateDirectory(outputPath);
                }

                string? awsAccessKeyId = null, awsSecretAccessKey = null, awsSessionToken = null, awsAccountIdArg = null;
                if (!string.IsNullOrWhiteSpace(opts.AwsProfileName))
                {
                    var chain = new CredentialProfileStoreChain();
                    if (!chain.TryGetAWSCredentials(opts.AwsProfileName, out var awsCredentials))
                    {
                        Console.Error.WriteLine($"Failed to find the {opts.AwsProfileName} profile");
                        return (int)ExitCodes.AwsProfileNotFound;
                    }

                    // IAM Identity Center
                    if (awsCredentials is SSOAWSCredentials ssoCredentials)
                    {
                        ssoCredentials.Options.ClientName = "aws-access-graph";
                        ssoCredentials.Options.SsoVerificationCallback = args =>
                        {
                            Console.Error.WriteLine($"Launching SSO window to obtain credentials for the {opts.AwsProfileName} profile");
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = args.VerificationUriComplete,
                                UseShellExecute = true
                            });
                        };

                        var credentials = ssoCredentials.GetCredentials();
                        awsAccessKeyId = opts.AwsAccessKeyId ?? credentials.AccessKey;
                        awsSecretAccessKey = opts.AwsSecretAccessKey ?? credentials.SecretKey;
                        awsSessionToken = opts.AwsSessionToken ?? credentials.Token;
                        awsAccountIdArg = opts.AwsAccountId ?? ssoCredentials.AccountId;
                    }
                    else if (awsCredentials is AssumeRoleAWSCredentials assumeRoleCredentials)
                    {
                        Console.Error.WriteLine($"Reading env variables and command line argument overrides for credentials");
                        awsAccessKeyId = opts.AwsAccessKeyId ?? Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
                        awsSecretAccessKey = opts.AwsSecretAccessKey ?? Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
                        awsSessionToken = opts.AwsSessionToken ?? Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN");
                        awsAccountIdArg = opts.AwsAccountId ?? Environment.GetEnvironmentVariable("AWS_ACCOUNT_ID");

                        if ((string.IsNullOrWhiteSpace(awsAccessKeyId)
                            || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                            && string.IsNullOrWhiteSpace(awsSessionToken))
                        {
                            Console.Error.WriteLine($"Error: A profile name {opts.AwsProfileName} with a role assumption was specified, but AWS credentials were not provided.");
                            return (int)ExitCodes.AwsCredentialsNotSpecified;
                        }

                        Console.Error.WriteLine($"Attempting to gather AWS assume role credentials for the {opts.AwsProfileName} profile");
                        assumeRoleCredentials.Options.MfaTokenCodeCallback = () =>
                        {
                            Console.WriteLine($"Please enter MFA code for {assumeRoleCredentials.Options.MfaSerialNumber}:");
                            return Console.ReadLine();
                        };

                        var assumedCredentials = assumeRoleCredentials.GetCredentials();
                        awsAccessKeyId = assumedCredentials.AccessKey;
                        awsSecretAccessKey = assumedCredentials.SecretKey;
                        awsSessionToken = assumedCredentials.Token;
                    }
                    else
                    {
                        Console.Error.WriteLine($"Attempting to gather AWS credentials for the {opts.AwsProfileName} profile");
                        var credentials = awsCredentials.GetCredentials();
                        awsAccessKeyId = opts.AwsAccessKeyId ?? credentials.AccessKey;
                        awsSecretAccessKey = opts.AwsSecretAccessKey ?? credentials.SecretKey;
                        awsSessionToken = opts.AwsSessionToken ?? credentials.Token;
                        awsAccountIdArg = opts.AwsAccountId ?? Environment.GetEnvironmentVariable("AWS_ACCOUNT_ID");
                    }
                }
                else
                {
                    Console.Error.WriteLine($"Reading env variables and command line argument overrides for credentials");
                    awsAccessKeyId = opts.AwsAccessKeyId ?? Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
                    awsSecretAccessKey = opts.AwsSecretAccessKey ?? Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
                    awsSessionToken = opts.AwsSessionToken ?? Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN");
                    awsAccountIdArg = opts.AwsAccountId ?? Environment.GetEnvironmentVariable("AWS_ACCOUNT_ID");
                }

                if ((string.IsNullOrWhiteSpace(awsAccessKeyId)
                    || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                    && string.IsNullOrWhiteSpace(awsSessionToken)
                    && opts.NoFiles)
                {
                    Console.Error.WriteLine("Error: no-files was specified, but AWS credentials were not provided.");
                    return (int)ExitCodes.AwsCredentialsNotSpecified;
                }

                string[] awsAccountIds;

                if (string.IsNullOrWhiteSpace(awsAccountIdArg)
                    && string.IsNullOrWhiteSpace(awsAccessKeyId)
                    && string.IsNullOrWhiteSpace(awsSecretAccessKey))
                {
                    var files = Directory.GetFiles(dbPath, "aws-*-list.json", new EnumerationOptions { IgnoreInaccessible = true });
                    if (files.Any())
                    {
                        awsAccountIds = files
                            .Select(f => System.Text.RegularExpressions.Regex.Match(f, "aws-(?<aid>\\d{12})-").Groups["aid"].Value)
                            .Distinct()
                            .Where(a =>
                                files.Any(f => f.IndexOf($"aws-{a}-group-list.json") > -1)
                                && files.Any(f => f.IndexOf($"aws-{a}-policy-list.json") > -1)
                                && files.Any(f => f.IndexOf($"aws-{a}-role-list.json") > -1)
                                && files.Any(f => f.IndexOf($"aws-{a}-saml-idp-list.json") > -1)
                                && files.Any(f => f.IndexOf($"aws-{a}-user-list.json") > -1)
                            )
                            .ToArray();

                        Console.Error.WriteLine($"No AWS Account ID argument was specified, but {awsAccountIds.Length} were found with cached DbPath files, so using those.");
                    }
                    else
                    {
                        awsAccountIds = Array.Empty<string>();
                    }
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(awsAccountIdArg))
                    {
                        if (!string.IsNullOrWhiteSpace(awsSessionToken))
                        {
                            // Infer from session token.
                        }
                        else
                        {
                            Console.Error.WriteLine("Error: An AWS Account ID cannot be inferred and was not specified as a command line argument.");
                            Console.WriteLine($"awsAccountIdArg:    {(string.IsNullOrWhiteSpace(awsAccountIdArg) ? "SPECIFIED" : "UNSPECIFIED")}");
                            Console.WriteLine($"awsAccessKeyId:     {(string.IsNullOrWhiteSpace(awsAccessKeyId) ? "SPECIFIED" : "UNSPECIFIED")}");
                            Console.WriteLine($"awsSecretAccessKey: {(string.IsNullOrWhiteSpace(awsSecretAccessKey) ? "SPECIFIED" : "UNSPECIFIED")}");
                            Console.WriteLine($"awsSessionToken:    {(string.IsNullOrWhiteSpace(awsSessionToken) ? "SPECIFIED" : "UNSPECIFIED")}");
                            Console.Error.WriteLine("Hint: Maybe you're running this inside of aws-mfa or have env variables set for an AWS profile and did not intend to?");
                            return (int)ExitCodes.AwsAccountIdMissing;
                        }
                    }
                    awsAccountIds = new[] { awsAccountIdArg! };
                }

                var allNodes = new List<Node>();
                var allEdges = new List<Edge<Node, string>>();
                var accountRoleList = new Dictionary<string, List<Amazon.IdentityManagement.Model.RoleDetail>>();

                var actualAwsAccountIds = new List<string>();

                var oktaDomain = opts.OktaBaseUrl ?? Environment.GetEnvironmentVariable("OKTA_BASE_URL");
                var oktaApiToken = opts.OktaApiToken ?? Environment.GetEnvironmentVariable("OKTA_API_TOKEN");
                var (oktaGroups, oktaUsers, oktaGroupUsers) =
                    await AwsAccessGraph.OktaPolicies.OktaPolicyLoader.LoadOktaPolicyAsync(
                        oktaDomain: oktaDomain,
                        oktaApiToken: oktaApiToken,
                        outputDirectory: dbPath,
                        noFiles: opts.NoFiles,
                        forceRefresh: opts.Refresh || opts.RefreshOkta,
                        cancellationToken: cts.Token);

                foreach (var awsAccountId in awsAccountIds)
                {
                    Console.Error.WriteLine($"Processing AWS Account ID {awsAccountId}...");
                    var (awsGroups, awsPolicies, awsRoles, awsUsers, awsSamlIdPs, actualAwsAccountId) = await AwsAccessGraph.AwsPolicies.AwsPolicyLoader.LoadAwsPolicyAsync(
                        awsAccessKeyId: awsAccessKeyId,
                        awsSecretAccessKey: awsSecretAccessKey,
                        awsSessionToken: awsSessionToken,
                        awsAccountId: awsAccountId,
                        outputDirectory: dbPath,
                        noFiles: opts.NoFiles,
                        forceRefresh: opts.Refresh || opts.RefreshAws,
                        cancellationToken: cts.Token);

                    accountRoleList.Add(actualAwsAccountId, awsRoles);

                    var (nodes, edges) = GraphBuilder.BuildAws(
                        awsGroups,
                        awsPolicies,
                        awsRoles,
                        awsUsers,
                        awsSamlIdPs,
                        oktaGroups,
                        oktaUsers,
                        oktaGroupUsers,
                        opts.Verbose,
                        !opts.AwsServicePrefix.Contains(',')
                            ? new string[] { opts.AwsServicePrefix }
                            : opts.AwsServicePrefix.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries),
                        opts.NoPrune,
                        noIdentities: opts.NoIdentities);

                    allNodes.AddRange(nodes);
                    allEdges.AddRange(edges);

                    Console.Error.WriteLine($"Processing complete for AWS Account ID {actualAwsAccountId}");
                    actualAwsAccountIds.Add(actualAwsAccountId);
                }

                // Now get last-accessed data.
                var policyServices = allNodes
                    .Where(n => n.Type == NodeType.AwsInlinePolicy
                        || n.Type == NodeType.AwsPolicy)
                    .Distinct()
                    .ToDictionary(
                        k => k.Arn!,
                        v => GraphSearcher.FindServicesAttachedTo(allEdges, v).Select(s => s.service).ToArray()
                    );

                foreach (var awsAccountId in actualAwsAccountIds)
                {
                    await AwsAccessGraph.AwsPolicies.AwsPolicyLoader.LoadAwsLastAccessedReportsAsync(
                        awsAccessKeyId: awsAccessKeyId,
                        awsSecretAccessKey: awsSecretAccessKey,
                        awsSessionToken: awsSessionToken,
                        awsAccountId: awsAccountId,
                        outputDirectory: dbPath,
                        noFiles: opts.NoFiles,
                        forceRefresh: opts.Refresh || opts.RefreshAws,
                        roleList: accountRoleList[awsAccountId],
                        policyServices: policyServices,
                        cancellationToken: cts.Token);
                }

                // Dedupe nodes and repair edges.
                var dedupedNodes = allNodes.Distinct().ToList();
                if (allNodes.Count != dedupedNodes.Count)
                    Console.WriteLine($"Deduped {allNodes.Count} nodes into {dedupedNodes.Count} nodes.");
                var dedupedEdges = allEdges.Distinct()
                    .Select(e => new Edge<Node, string>(
                        dedupedNodes.Single(d => string.CompareOrdinal(e.Source.Name, d.Name) == 0
                        && e.Source.Type == d.Type
                        && string.CompareOrdinal(e.Source.Arn, d.Arn) == 0),
                        dedupedNodes.Single(d => string.CompareOrdinal(e.Destination.Name, d.Name) == 0
                        && e.Destination.Type == d.Type
                        && string.CompareOrdinal(e.Destination.Arn, d.Arn) == 0),
                        e.EdgeData)).ToList();
                if (allEdges.Count != dedupedEdges.Count)
                    Console.WriteLine($"Deduped {allEdges.Count} edges into {dedupedEdges.Count} edges.");

                allNodes = dedupedNodes;
                allEdges = dedupedEdges;

                // Write graph out to DGML file
                if (opts.OutputDGML)
                {
                    Console.Error.WriteLine("Writing directed graph markup language file... ");
                    var dgmlPath = Path.Combine(outputPath, "graph.dgml");
                    DgmlSerializer.Write(dgmlPath, allNodes, allEdges);
                    Console.Error.WriteLine("Writing directed graph markup language file... [\u2713]");
                }

                // Write graph out to Graphviz DOT file
                if (opts.OutputGraphviz)
                {
                    Console.Error.WriteLine("Writing Graphviz DOT file... ");
                    var dotPath = Path.Combine(outputPath, "graph.dot");
                    await DotSerializer.WriteAsync(
                        dotPath,
                        allNodes,
                        allEdges,
                        cts.Token);
                    Console.Error.WriteLine("Writing Graphviz DOT file... [\u2713]");
                }

                // Who has access to Glue?
                var pathNodeName = (Node n) =>
                {
                    var isArn = Amazon.Arn.TryParse(n.Arn, out Amazon.Arn arn);
                    var arnSuffix = isArn && actualAwsAccountIds.Count > 1 ? $"({arn.AccountId})" : string.Empty;
                    return n.Type switch
                    {
                        NodeType.AwsInlinePolicy => $"AwsInlinePolicy:{n.Name}",
                        NodeType.AwsPolicy => $"AwsIamPolicy:{n.Name}{arnSuffix}",
                        NodeType.AwsGroup => $"AwsIamGroup:{n.Name}{arnSuffix}",
                        NodeType.AwsRole => $"AwsIamRole:{n.Name}{arnSuffix}",
                        NodeType.AwsUser => $"AwsIamUser:{n.Name}{arnSuffix}",
                        NodeType.AwsService => $"{n.Name}",
                        NodeType.OktaUser => $"OktaUser:{n.Name}",
                        NodeType.OktaGroup => $"OktaGroup:{n.Name}",
                        NodeType.Identity => $"ID:{n.Name}",
                        _ => n.Name,
                    };
                };

                foreach (var servicePrefix in !opts.AwsServicePrefix.Contains(',')
                    ? new string[] { opts.AwsServicePrefix }
                    : opts.AwsServicePrefix.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    var targetService = allNodes.FindServiceNode(servicePrefix.ToLowerInvariant());
                    if (default(Node).Equals(targetService))
                    {
                        Console.Error.WriteLine($"Unable to find any service node named '{servicePrefix.ToLowerInvariant()}'.  Perhaps you have no cached db files for the specified account/service?");
                        return (int)ExitCodes.TargetServiceNotFound;
                    }
                    else
                    {
                        Console.Error.WriteLine($"Reporting on service {servicePrefix}");
                        var pathReport = Path.Combine(outputPath, $"authorization-paths-{targetService.Name}.txt");
                        using var fs = opts.NoFiles ? null : new FileStream(pathReport, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous });
                        using var sw = opts.NoFiles ? null : new StreamWriter(fs!);
                        var writer = opts.NoFiles ? Console.Out : sw!;

                        await writer.WriteLineAsync($"Report of accesses to {Constants.AwsServicePolicyNames[servicePrefix]} generated on {DateTime.UtcNow:O} for account(s) {actualAwsAccountIds.Aggregate((c, n) => c + "," + n)}.");
                        foreach (var u in allEdges
                            .FindUsersAttachedTo(targetService)
                            .GroupBy(u => u.source)
                            .OrderBy(u => u.Key.Name))
                        {
                            await writer.WriteLineAsync($"{targetService.Name}: {pathNodeName(u.Key)}");
                            foreach (var p in u)
                            {
                                var pathString = p.path.Select(e => pathNodeName(e.Source)).Aggregate((c, n) => $"{c}->{n}");
                                await writer.WriteLineAsync($"\tpath: {pathString}->{pathNodeName(targetService)}");
                            }
                        }
                    }
                }

                Console.Out.WriteLine($"{Environment.NewLine}Done.");
                return 0;
            }
            catch (Amazon.IdentityManagement.AmazonIdentityManagementServiceException ex)
            {
                Console.Error.WriteLine($"AWS IAM error: {ex.Message}");
                cts.Cancel();
                return (int)ExitCodes.AwsIamException;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error!{Environment.NewLine}{ex}");
                cts.Cancel();
                return (int)ExitCodes.UnhandledError; // Unhandled error
            }
        },
        errs => Task.FromResult((int)ExitCodes.ErrorParsingCommandLineArguments));
    }
}