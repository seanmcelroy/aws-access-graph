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

namespace AwsAccessGraph.AwsPolicies
{
    public static class RoleAnalyzer
    {
        public static RoleAnalyzerResult Analyze(string assumeRolePolicyDocument, IEnumerable<ManagedPolicyDetail> policyList, CancellationToken cancellationToken = default(CancellationToken))
        {
            var arpDoc = Uri.UnescapeDataString(assumeRolePolicyDocument);
            var arPolicy = JsonSerializer.Deserialize<AwsPolicy>(arpDoc);

            var rolesThatCanAssume = arPolicy.Statement
                .Where(s=> s.Principal != null)
                .Where(s=> s.Action.Any(a => string.Compare(a, "sts:AssumeRole", StringComparison.OrdinalIgnoreCase) == 0))
                .SelectMany(s => s.Principal!)
                .Where(p => string.Compare(p.Key, "AWS", StringComparison.OrdinalIgnoreCase) == 0)
                .SelectMany(p => p.Value.Where(x => x.IndexOf(":role/", StringComparison.OrdinalIgnoreCase) > 0))
                .ToHashSet();

            var federationsThatCanAssume = arPolicy.Statement
                .Where(s=> s.Principal != null)
                .Where(s=> s.Action.Any(a => string.Compare(a, "sts:AssumeRoleWithSAML", StringComparison.OrdinalIgnoreCase) == 0))
                .SelectMany(s => s.Principal!)
                .Where(p => string.Compare(p.Key, "Federated", StringComparison.OrdinalIgnoreCase) == 0)
                .SelectMany(p => p.Value.Where(x => x.IndexOf(":saml-provider/", StringComparison.OrdinalIgnoreCase) > 0))
                .ToHashSet();

            return new RoleAnalyzerResult
            {
                IamRootAllowed = arPolicy.Statement.SelectMany(s =>
                    (s.Principal != null)
                        ? s.Principal
                            .Where(p => string.Compare(p.Key, "AWS", StringComparison.OrdinalIgnoreCase) == 0)
                            .SelectMany(p => p.Value.Where(x => x.EndsWith(":root", StringComparison.OrdinalIgnoreCase)))
                        : []).Any(),

                TrustedEntitiesThatCanAssume =
                    rolesThatCanAssume.Union(federationsThatCanAssume).ToHashSet()
            };
        }
    }
}