﻿/*
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
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using AwsAccessGraph;
using AwsAccessGraph.AwsPolicies;
using AwsAccessGraph.DirectedGraphMarkupLanguage;
using AwsAccessGraph.Graphviz;
using CommandLine;
using CsvHelper;
using YamlDotNet.Serialization.NodeTypeResolvers;
using static AwsAccessGraph.Constants;

internal class Program
{
    public readonly record struct IgnoreRecord
    {
        public readonly string Identity { get; init; }
        public readonly string Service { get; init; }
    }

    private static readonly List<IgnoreRecord> IgnoreRecords = [];

    private static async Task<int> Main(string[] args)
    {
        Console.Error.WriteLine("aws-access-graph  Copyright (C) 2024  Sean McElroy");
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
                !AwsServicePolicyNames.ContainsKey(opts.AwsServicePrefix.ToLowerInvariant()))
            {
                Console.Error.WriteLine($"Service {opts.AwsServicePrefix} not specified.  Must be a valid AWS service prefix or a common-delimited list of valid service prefixes");
                return (int)ExitCodes.InvalidAwsServicePrefix;
            }

            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += delegate
            {
                cts.Cancel();
            };

            try
            {
                var configPath = Path.Combine(Environment.CurrentDirectory, opts.ConfigPath);
                if (!Directory.Exists(configPath))
                {
                    if (opts.Verbose)
                        Console.Error.WriteLine($"VERBOSE: Cannot find conf directory in working path ({configPath}), so skipping.");
                }
                else
                {
                    Console.Error.WriteLine("Reading configurations from conf directory... ");
                    ReadConfigurations(configPath, opts.Verbose);
                    Console.Error.WriteLine("Reading configurations from conf directory... [\u2713]");
                }

                var dbPath = Path.Combine(Environment.CurrentDirectory, opts.DbPath);
                if (!Directory.Exists(dbPath))
                {
                    Console.Error.WriteLine($"INFO: Cannot find db directory in working path. Creating: {dbPath}");
                    Directory.CreateDirectory(dbPath);
                }

                var outputPath = Path.Combine(Environment.CurrentDirectory, opts.OutputPath);
                if (!Directory.Exists(outputPath))
                {
                    Console.Error.WriteLine($"INFO: Cannot find output directory in working path. Creating: {outputPath}");
                    Directory.CreateDirectory(outputPath);
                }

                var allNodes = new List<Node>();
                var allEdges = new List<IEdge<Node>>();
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

                var accts = await GetAwsAccountIds(
                    dbPath,
                    opts,
                    () => GetAwsCredentials(opts, dbPath),
                    cts.Token);

                foreach (var awsAccountId in accts)
                {
                    Console.Error.WriteLine($"Processing AWS Account ID {awsAccountId}...");
                    var (awsGroups, awsPolicies, awsRoles, awsUsers, awsSamlIdPs, permissionSetList, permissionSetManagedPolicies, permissionSetInlinePolicies, identityStoreUsers, identityStoreGroups, identityStoreGroupMemberships, permissionSetAssignments, actualAwsAccountId) = await AwsPolicyLoader.LoadAwsPolicyAsync(
                        () => GetAwsCredentials(opts, dbPath),
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
                        permissionSetList,
                        permissionSetManagedPolicies,
                        permissionSetInlinePolicies,
                        identityStoreUsers,
                        identityStoreGroups,
                        identityStoreGroupMemberships,
                        permissionSetAssignments,
                        oktaGroups,
                        oktaUsers,
                        oktaGroupUsers,
                        opts.Verbose,
                        !opts.AwsServicePrefix.Contains(',')
                            ? [opts.AwsServicePrefix]
                            : opts.AwsServicePrefix.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries),
                        opts.NoPrune);

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

                /*TODO: Use this data.  foreach (var awsAccountId in actualAwsAccountIds)
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
                }*/

                // Dedupe nodes and repair edges.
                var dedupedNodes = allNodes.Distinct().ToList();
                if (allNodes.Count != dedupedNodes.Count)
                    Console.WriteLine($"Deduped {allNodes.Count} nodes into {dedupedNodes.Count} nodes.");
                var dedupedEdges = allEdges.Distinct()
                    .Select(e =>
                    {
                        /*if ((e.Source.Type == NodeType.OktaUser || e.Source.Type == NodeType.AwsUser) && opts.NoIdentities)
                            return default(Edge<Node, string>);
                        if ((e.Destination.Type == NodeType.OktaUser || e.Destination.Type == NodeType.AwsUser) && opts.NoIdentities)
                            return default(Edge<Node, string>);
                        */
                        var sourceNode = dedupedNodes.SingleOrDefault(d => string.CompareOrdinal(e.Source.Name, d.Name) == 0
                            && e.Source.Type == d.Type
                            && string.CompareOrdinal(e.Source.Arn, d.Arn) == 0);
                        if (sourceNode == default)
                        {
                            Console.Error.WriteLine($"WARN: Could not find source node {e.Source.Name}");
                            //return default(Edge<Node, string>);
                        }
                        var destNode = dedupedNodes.Single(d => string.CompareOrdinal(e.Destination.Name, d.Name) == 0
                                            && e.Destination.Type == d.Type
                                            && string.CompareOrdinal(e.Destination.Arn, d.Arn) == 0);
                        if (destNode == default)
                        {
                            Console.Error.WriteLine($"WARN: Could not find destination node {e.Destination.Name}");
                            //return default(Edge<Node, string>);
                        }

                        var edgeType = e.GetType();
                        var newEdge = Activator.CreateInstance(edgeType, sourceNode, destNode, e.EdgeData);
                        return newEdge;
                    })
                    .Where(e => !e!.Equals(default(Edge<Node, string>)))
                    .ToList();
                if (allEdges.Count != dedupedEdges.Count)
                    Console.WriteLine($"Deduped {allEdges.Count} edges into {dedupedEdges.Count} edges.");

                allNodes = dedupedNodes;
                allEdges = dedupedEdges.Select(x => (IEdge<Node>)x!).ToList();

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

                // Authorization text reports (console or standard out)
                if (opts.OutputTextReport)
                {
                    Console.Error.WriteLine("Writing authorization text reports... ");
                    var dotPath = Path.Combine(outputPath, "graph.dot");
                    var (ignoredIdentities, ignoredPaths) = await WriteAuthorizationReports(actualAwsAccountIds, allNodes, allEdges, outputPath, opts, cts.Token);
                    if (ignoredPaths > 0)
                        Console.Error.WriteLine($"\tIgnored {ignoredPaths} paths across {ignoredIdentities} identities according to {IgnoreRecords.Count} specified ignore rules.");
                    Console.Error.WriteLine("..Wrote authorization text reports... [\u2713]");
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

    public static (
        string? awsAccessKeyId,
        string? awsSecretAccessKey,
        string? awsSessionToken,
        string? awsAccountIdArg,
        ExitCodes? exitCode) GetAwsCredentials(CommandLineOptions opts, string dbPath)
    {
        string? awsAccessKeyId = null, awsSecretAccessKey = null, awsSessionToken = null, awsAccountIdArg = null;
        if (!string.IsNullOrWhiteSpace(opts.AwsProfileName))
        {
            var chain = new CredentialProfileStoreChain();
            if (!chain.TryGetAWSCredentials(opts.AwsProfileName, out var awsCredentials))
            {
                Console.Error.WriteLine($"Failed to find the {opts.AwsProfileName} profile");
                return (null, null, null, null, ExitCodes.AwsProfileNotFound);
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
                    return (null, null, null, null, ExitCodes.AwsCredentialsNotSpecified);
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
            return (null, null, null, null, ExitCodes.AwsCredentialsNotSpecified);
        }

        return (awsAccessKeyId, awsSecretAccessKey, awsSessionToken, awsAccountIdArg, null);
    }

    public static void ReadConfigurations(string configPath, bool verbose)
    {
        // IGNORE.csv
        var ignoreCsvPath = Path.Combine(configPath, "IGNORE.csv");
        IgnoreRecords.Clear();
        if (File.Exists(ignoreCsvPath))
        {
            try
            {
                using var sr = new StreamReader(ignoreCsvPath);
                using var csv = new CsvReader(sr, CultureInfo.InvariantCulture);
                IgnoreRecords.AddRange(csv.GetRecords<IgnoreRecord>());
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR: EXCEPTION READING IGNORE FILE!{Environment.NewLine}{ex}");
                Environment.Exit((int)ExitCodes.UnhandledError);
            }
        }
        else if (verbose)
            Console.Error.WriteLine($"VERBOSE: IGNORE file not found, skipping.");
    }

    /// <summary>
    /// Finds the AWS accounts through which to enumerate.
    /// 
    /// If an account is specified in the command line arguments, it is used.
    /// Otherwise, if cached files are present, the accounts represented in that
    /// cache are used.  Otherwise, credentials are used to interrogate AWS STS
    /// to identify the account associated with those credentials.
    /// </summary>
    /// <param name="dbPath">The path at which cached files may be located</param>
    /// <param name="opts">Command line options provided when the program was invoked</param>
    /// <param name="awsCredentialLoader">A function that obtains AWS credentials to interrogate STS, if necessary </param>
    /// <param name="cancellationToken">A cancellation token used to abort this operation</param>
    /// <returns>An array of AWS account IDs (account numbers)</returns>
    public static async Task<string[]> GetAwsAccountIds(string dbPath, CommandLineOptions opts, Func<(
        string? awsAccessKeyId,
        string? awsSecretAccessKey,
        string? awsSessionToken,
        string? awsAccountIdArg,
        ExitCodes? exitCode)> awsCredentialLoader,
        CancellationToken cancellationToken)
    {
        string[] awsAccountIds = [];

        // If an AWS creds are specified as actual command line arguments, presume we will be reading account number using it.
        var readAccountFromSts = false;
        if (string.IsNullOrWhiteSpace(opts.AwsAccountId)
            && (
                !string.IsNullOrWhiteSpace(opts.AwsAccessKeyId)
                || !string.IsNullOrWhiteSpace(opts.AwsSecretAccessKey)
                || !string.IsNullOrWhiteSpace(opts.AwsSessionToken)
                || !string.IsNullOrWhiteSpace(opts.AwsProfileName)
            )
        )
        {
            if (opts.Verbose)
                Console.Error.WriteLine("VERBOSE: Because credentials were specified as command line arguments, attempting to read account number using them.");
            var stsClient = Globals.GetStsClientFactory(awsCredentialLoader)!;
            if (stsClient != null)
            {
                var identity = await stsClient.Value.GetCallerIdentityAsync(new Amazon.SecurityToken.Model.GetCallerIdentityRequest(), cancellationToken);
                awsAccountIds = [.. awsAccountIds, identity.Account];
                readAccountFromSts = true;
            }
        }

        if (awsAccountIds.Length == 0 && !string.IsNullOrWhiteSpace(opts.AwsAccountId))
            awsAccountIds = [opts.AwsAccountId];

        // Deduce from local file cache
        if (awsAccountIds.Length == 0)
        {
            var files = Directory.GetFiles(dbPath, "aws-*-list.json", new EnumerationOptions { IgnoreInaccessible = true });
            if (files.Length != 0)
            {
                awsAccountIds = files
                    .Select(f => Regex.Match(f, "aws-(?<aid>\\d{12})-").Groups["aid"].Value)
                    .Distinct()
                    .Where(a =>
                        files.Any(f => f.IndexOf($"aws-{a}-group-list.json") > -1)
                        && files.Any(f => f.IndexOf($"aws-{a}-policy-list.json") > -1)
                        && files.Any(f => f.IndexOf($"aws-{a}-role-list.json") > -1)
                        && files.Any(f => f.IndexOf($"aws-{a}-saml-idp-list.json") > -1)
                        && files.Any(f => f.IndexOf($"aws-{a}-user-list.json") > -1)
                    )
                    .ToArray();

                if (string.IsNullOrWhiteSpace(opts.AwsAccountId) && awsAccountIds.Length > 0)
                    Console.Error.WriteLine($"No AWS Account ID argument was specified, but {awsAccountIds.Length} were found with cached DbPath files, so using those.");
            }
        }

        var forceRefresh = opts.Refresh || opts.RefreshAws;
        if (forceRefresh && !readAccountFromSts)
        {
            var stsClient = Globals.GetStsClientFactory(awsCredentialLoader)!;
            if (stsClient != null)
            {
                var identity = await stsClient.Value.GetCallerIdentityAsync(new Amazon.SecurityToken.Model.GetCallerIdentityRequest(), cancellationToken);
                awsAccountIds = [.. awsAccountIds, identity.Account];
                readAccountFromSts = true;
            }
        }

        return awsAccountIds;
    }

    public static async Task<(int ignoredIdentities, int ignoredPaths)> WriteAuthorizationReports(
        List<string> awsAccountIds,
        List<Node> allNodes,
        List<IEdge<Node>> allEdges,
        string outputPath,
        CommandLineOptions opts,
        CancellationToken cancellationToken)
    {
        List<string> ignoredIdentities = [];
        int ignoredPaths = 0;

        string pathNodeName(Node n)
        {
            var isArn = Amazon.Arn.TryParse(n.Arn, out Amazon.Arn arn);
            var arnSuffix = isArn && awsAccountIds.Count > 1 ? $"({arn.AccountId})" : string.Empty;
            return n.Type switch
            {
                NodeType.AwsInlinePolicy => $"AwsInlinePolicy:{n.Name}",
                NodeType.AwsPolicy => $"AwsIamPolicy:{n.Name}{arnSuffix}",
                NodeType.AwsGroup => $"AwsIamGroup:{n.Name}{arnSuffix}",
                NodeType.AwsRole => $"AwsIamRole:{n.Name}{arnSuffix}",
                NodeType.AwsUser => $"AwsIamUser:{n.Name}{arnSuffix}",
                NodeType.AwsService => $"{n.Name}",
                NodeType.AwsPermissionSet => $"AwsPermissionSet:{n.Name}{arnSuffix}",
                NodeType.OktaUser => $"OktaUser:{n.Name}",
                NodeType.OktaGroup => $"OktaGroup:{n.Name}",
                NodeType.AwsIdentityStoreUser => $"IdentityStoreUser:{n.Name}",
                NodeType.AwsIdentityStoreGroup => $"IdentityStoreGroup:{n.Name}",
                NodeType.IdentityPrincipal => $"ID:{n.Name}",
                _ => n.Name,
            };
        }

        foreach (var servicePrefix in !opts.AwsServicePrefix.Contains(',')
                            ? [opts.AwsServicePrefix]
                            : opts.AwsServicePrefix.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var targetService = allNodes.FindServiceNode(servicePrefix.ToLowerInvariant());
            if (default(Node).Equals(targetService))
            {
                Console.Error.WriteLine($"\tUnable to find any service node named '{servicePrefix.ToLowerInvariant()}'.  Perhaps you have no cached db files for the specified account/service?");
                Environment.Exit((int)ExitCodes.TargetServiceNotFound);
                return (0, 0);
            }

            Console.Error.WriteLine($"\tReporting on service {servicePrefix}");
            var pathReport = Path.Combine(outputPath, $"authorization-paths-{targetService.Name}.txt");
            using var fs = opts.NoFiles ? null : new FileStream(pathReport, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous });
            using var sw = opts.NoFiles ? null : new StreamWriter(fs!);
            var writer = opts.NoFiles ? Console.Out : sw!;

            var targeting = string.IsNullOrWhiteSpace(opts.AwsAccountId) || awsAccountIds.All(a => string.CompareOrdinal(a, opts.AwsAccountId) == 0)
                ? string.Empty
                : $" targeting account {opts.AwsAccountId}";

            await writer.WriteLineAsync($"Report of accesses to {AwsServicePolicyNames[servicePrefix]} generated on {DateTime.UtcNow:O} for account(s) {awsAccountIds.Aggregate((c, n) => c + "," + n)}{targeting}.");

            var reportEdgeList = opts.NoIdentities
                ? allEdges.FindIdentityGroupsAttachedTo(targetService)
                : allEdges.FindIdentityPrincipalsAttachedTo(targetService);

            Dictionary<string, List<string>> edgePaths = [];
            List<string>? currentEdgePath = null;

            foreach (var u in reportEdgeList
                .GroupBy(u => u.source)
                .OrderBy(u => u.Key.Name))
            {
                currentEdgePath = null;

                foreach (var (source, path) in u)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        await writer.WriteLineAsync("PROCESS ABORTED, REPORT INCOMPLETE");
                        writer.Flush(); // No async because we are cancelling async.
                        return (0, 0);
                    }

                    bool readOnly = true;
                    //List<string> resources = [];
                    foreach (var e in path)
                    {
                        if (e.EdgeData is PolicyAnalyzerResult result)
                        {
                            readOnly = result.ReadOnly(servicePrefix);
                            /*resources.AddRange(result.Stanzas
                                .Where(s => !s.Deny && s.Resources != null)
                                .SelectMany(s => s.Resources!)
                                .Select(r => Amazon.Arn.IsArn(r)
                                    ? Amazon.Arn.Parse(r).Resource
                                    : r)
                                .Where(r =>
                                    r.Length > 1
                                    && !Regex.IsMatch(r, "[a-z0-9\\-]+/\\*") // resource-name/* like key-pair/* and instance/*.  Don't count 'any'
                                    && string.CompareOrdinal(r, "user/${aws:userid}") != 0 // Don't count users editing themselves.
                                ));*/
                        }
                    };

                    /*if (resources.Count > 0)
                    {
                        Console.Write(resources.Distinct().Aggregate((c, n) => $"{c},{n}"));
                    }*/

                    string finalServiceString = $"{pathNodeName(targetService)}{(readOnly ? string.Empty : "(WRITE)")}";

                    var shouldIgnore = false;
                    IgnoreRecord? matchedIgnore = null;
                    foreach (var ignored in IgnoreRecords)
                    {
                        var ignore1 = false;
                        var ignore2 = false;

                        foreach (var edge in path)
                        {
                            switch (edge.Source.Type)
                            {
                                case NodeType.IdentityPrincipal:
                                case NodeType.AwsUser:
                                case NodeType.AwsGroup:
                                case NodeType.OktaUser:
                                case NodeType.OktaGroup:
                                case NodeType.AwsIdentityStoreUser:
                                case NodeType.AwsIdentityStoreGroup:
                                    if (string.Compare(pathNodeName(edge.Source), ignored.Identity, StringComparison.OrdinalIgnoreCase) == 0)
                                        ignore1 = true;
                                    break;
                            }
                            switch (edge.Destination.Type)
                            {
                                case NodeType.AwsService:
                                    if (string.Compare(finalServiceString, ignored.Service, StringComparison.OrdinalIgnoreCase) == 0)
                                        ignore2 = true;
                                    break;
                            }
                        }

                        shouldIgnore = ignore1 && ignore2;
                        if (shouldIgnore)
                        {
                            matchedIgnore = ignored;
                            break;
                        }
                    }

                    var pathString = path.Select(e => pathNodeName(e.Source)).Aggregate((c, n) => $"{c}->{n}");
                    var finalPathString = $"{pathString}->{finalServiceString}";

                    if (shouldIgnore && matchedIgnore != null)
                    {
                        ignoredPaths++;
                        if (!ignoredIdentities.Contains(u.Key.Name))
                            ignoredIdentities.Add(u.Key.Name);
                        if (opts.Verbose)
                            Console.Error.WriteLine($"\tVERBOSE: Ignore rule ({matchedIgnore.Value.Identity},{matchedIgnore.Value.Service}) matched for: {finalPathString}");
                        continue; // to next path for this user
                    }

                    // Add resources...


                    if (currentEdgePath == null)
                    {
                        // Do it this way so we don't print a header record if all the paths were ignored.
                        var edgeName = $"{targetService.Name}: {pathNodeName(u.Key)}";
                        currentEdgePath = [];
                        edgePaths.Add(edgeName, currentEdgePath);
                    }

                    currentEdgePath.Add($"\tpath: {finalPathString}");
                }
            }

            // Dedupe edges
            foreach (var edgePath in edgePaths)
            {
                await writer.WriteLineAsync(edgePath.Key);
                foreach (var path in edgePath.Value.Distinct())
                {
                    await writer.WriteLineAsync(path);
                }
            }
            await writer.FlushAsync(cancellationToken);
        }

        return (ignoredIdentities.Count, ignoredPaths);
    }
}