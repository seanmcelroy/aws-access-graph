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
            if (!Constants.AwsServicePolicyNames.ContainsKey(opts.AwsServicePrefix.ToLowerInvariant()))
            {
                return (int)ExitCodes.InvalidAwsServicePrefix;
            }

            try
            {
                var cts = new CancellationTokenSource();
                Console.CancelKeyPress += delegate
                {
                    cts.Cancel();
                };

                var dbPath = Path.Combine(Environment.CurrentDirectory, opts.DbPath);
                var outputPath = Path.Combine(Environment.CurrentDirectory, opts.OutputPath);

                var awsAccessKeyId = opts.AwsAccessKeyId ?? Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
                var awsSecretAccessKey = opts.AwsSecretAccessKey ?? Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
                var awsSessionToken = opts.AwsSessionToken ?? Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN");
                var awsAccountIdArg = opts.AwsAccountId ?? Environment.GetEnvironmentVariable("AWS_ACCOUNT_ID");

                if ((string.IsNullOrWhiteSpace(awsAccessKeyId)
                    || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                    && opts.NoFiles)
                {
                    Console.Error.WriteLine("Error: no-files was specified, but AWS credentials were not provided.");
                    return (int)ExitCodes.AwsCredentialsNotSpecified;
                }

                string?[] awsAccountIds;

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
                        awsAccountIds = Array.Empty<string>();
                }
                else
                    awsAccountIds = new[] { awsAccountIdArg };

                var allNodes = new List<Node>();
                var allEdges = new List<Edge<Node, string>>();

                foreach (var awsAccountId in awsAccountIds)
                {
                    Console.Error.WriteLine($"Processing AWS Account ID {awsAccountId}...");

                    var (awsGroups, awsPolicies, awsRoles, awsUsers, awsSamlIdPs) = await AwsAccessGraph.AwsPolicies.AwsPolicyLoader.LoadAwsPolicyAsync(
                        awsAccessKeyId: awsAccessKeyId,
                        awsSecretAccessKey: awsSecretAccessKey,
                        awsSessionToken: awsSessionToken,
                        awsAccountId: awsAccountId,
                        outputDirectory: dbPath,
                        noFiles: opts.NoFiles,
                        forceRefresh: opts.Refresh || opts.RefreshAws,
                        cancellationToken: cts.Token);

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
                        opts.AwsServicePrefix,
                        opts.NoPrune,
                        noIdentities: opts.NoIdentities);

                    allNodes.AddRange(nodes);
                    allEdges.AddRange(edges);

                    Console.Error.WriteLine($"Processing complete for AWS Account ID {awsAccountId}");
                }

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
                    switch (n.Type)
                    {
                        case NodeType.AwsInlinePolicy: return $"AwsInlinePolicy:{n.Name}";
                        case NodeType.AwsPolicy: return $"AwsIamPolicy:{n.Name}";
                        case NodeType.AwsGroup: return $"AwsIamGroup:{n.Name}";
                        case NodeType.AwsRole: return $"AwsIamRole:{n.Name}";
                        case NodeType.AwsUser: return $"AwsIamUser:{n.Name}";
                        case NodeType.AwsService: return $"{n.Name}";
                        case NodeType.OktaUser: return $"OktaUser:{n.Name}";
                        case NodeType.OktaGroup: return $"OktaGroup:{n.Name}";
                        case NodeType.Identity: return $"ID:{n.Name}";
                        default: return n.Name;
                    }
                };

                var targetService = allNodes.FindServiceNode(opts.AwsServicePrefix.ToLowerInvariant());
                {
                    var pathReport = Path.Combine(outputPath, "authorization-paths.txt");
                    using (var fs = opts.NoFiles ? null : new FileStream(pathReport, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous }))
                    using (var sw = opts.NoFiles ? null : new StreamWriter(fs!))
                    {
                        var writer = opts.NoFiles ? Console.Out : sw!;

                        await writer.WriteLineAsync($"Report of accesses to {Constants.AwsServicePolicyNames[opts.AwsServicePrefix]} generated on {DateTime.UtcNow.ToString("O")}");
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
            catch (Amazon.IdentityManagement.AmazonIdentityManagementServiceException amse)
            {
                Console.Error.WriteLine($"AWS IAM error: {amse.Message}");
                return (int)ExitCodes.AwsIamException;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error!{Environment.NewLine}{ex}");
                return (int)ExitCodes.UnhandledError; // Unhandled error
            }
        },
        errs => Task.FromResult((int)ExitCodes.ErrorParsingCommandLineArguments));
    }
}