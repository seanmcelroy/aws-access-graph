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

using System.Text.Json;
using Amazon.IdentityManagement.Model;
using System.Text.RegularExpressions;

namespace AwsAccessGraph.AwsPolicies
{
    public static class PolicyAnalyzer
    {
        private static string WildcardToRegularExpression(string value) =>
            $"^{Regex.Escape(value).Replace("\\?", ".").Replace("\\*", ".*")}$";

        public static PolicyAnalyzerResult Analyze(
            PolicyArn policyArn,
            string policyDocument,
            IEnumerable<RoleDetail> roleList,
            string[] limitToAwsServicePrefixes)
        {
            AwsPolicy policy;
            try
            {
                policy = JsonSerializer.Deserialize<AwsPolicy>(policyDocument);
            }
            catch (JsonException je)
            {
                Console.Error.WriteLine($"Could not parse document ({je.Message}):{Environment.NewLine}{policyDocument}{Environment.NewLine}");
                throw;
            }

            // Walk the statements and build stanzas.
            var stanzas = new List<PolicyStanza>();
            var assumeRoleTargets = new List<RoleArn>();
            foreach (var stmt in policy.Statement)
            {
                var deny = string.Compare(stmt.Effect, "Deny", StringComparison.OrdinalIgnoreCase) == 0;

                if (stmt.Action != null)
                {
                    // Some policies that deny based on condition block only would have no action block.
                    foreach (var action in stmt.Action)
                    {
                        if (string.CompareOrdinal(action, "*") == 0)
                        {
                            stanzas.Add(new PolicyStanza
                            {
                                Deny = deny,
                                Write = true,
                                Service = "*"
                            });
                            continue;
                        }

                        var actionParts = action.Split(':', 2, StringSplitOptions.None);

                        // There are some weird undocumented internal actions that should be ignored.
                        if (string.Compare(actionParts[0], "sysops-sap", StringComparison.OrdinalIgnoreCase) == 0
                            || string.Compare(actionParts[0], "ssm-sap", StringComparison.OrdinalIgnoreCase) == 0)
                        {
                            continue;
                        }

                        // Figure out read-only status of the stanza
                        var readOnly = false;
                        if (actionParts[1].StartsWith("Describe", StringComparison.OrdinalIgnoreCase)
                            || actionParts[1].StartsWith("Get", StringComparison.OrdinalIgnoreCase)
                            || actionParts[1].StartsWith("List", StringComparison.OrdinalIgnoreCase)
                            || actionParts[1].StartsWith("Search", StringComparison.OrdinalIgnoreCase)
                            )
                            readOnly = true;
                        else
                            readOnly = false;

                        // Is this an AssumeRole?
                        if (string.Compare(action, "sts:AssumeRole", StringComparison.OrdinalIgnoreCase) == 0
                            && stmt.Resource != null)
                        {
                            if (stmt.Resource.IsAny == true)
                                assumeRoleTargets.AddRange(roleList.Select(r => r.Arn));
                            else
                            {
                                foreach (var res in stmt.Resource)
                                {
                                    assumeRoleTargets.AddRange(roleList.Where(r => Regex.IsMatch(r.Arn, WildcardToRegularExpression(res))).Select(r => r.Arn));
                                }
                            }
                        }

                        //if (!Constants.AwsServicePolicyNames.TryGetValue(actionParts[0].ToLowerInvariant(), out string? awsService))
                        //    awsService = $"UNKNOWN {actionParts[0]}";

                        if (limitToAwsServicePrefixes == null
                            || limitToAwsServicePrefixes.Length == 0
                            || limitToAwsServicePrefixes.Any(p => string.Compare(actionParts[0], p, StringComparison.OrdinalIgnoreCase) == 0))
                        {
                            stanzas.Add(new PolicyStanza
                            {
                                Deny = deny,
                                Write = !readOnly,
                                Service = actionParts[0].ToLowerInvariant(), //awsService
                                ServiceActions = actionParts,
                                Resources = stmt.Resource == null ? null : (stmt.Resource.IsAny ? null : [.. stmt.Resource])
                            });
                        }
                    }
                }
            }

            return new PolicyAnalyzerResult
            {
                PolicyArn = policyArn,
                Stanzas = stanzas,
                AssumeRoleTargets = assumeRoleTargets
            };
        }
    }
}