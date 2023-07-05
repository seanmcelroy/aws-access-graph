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

using Amazon.IdentityManagement.Model;
using AwsAccessGraph.AwsPolicies;
using AwsAccessGraph.OktaPolicies;

namespace AwsAccessGraph
{
    public static class GraphBuilder
    {
        public static (List<Node> nodes, List<Edge<Node, string>> edges) BuildAws(
            IEnumerable<GroupDetail> awsGroups,
            IEnumerable<ManagedPolicyDetail> awsPolicies,
            IEnumerable<RoleDetail> awsRoles,
            IEnumerable<UserDetail> awsUsers,
            IEnumerable<SAMLProviderListEntry> awsSamlIdPs,
            IEnumerable<OktaGroup> oktaGroups,
            IEnumerable<OktaUser> oktaUsers,
            Dictionary<OktaGroupId, OktaGroupMember[]> oktaGroupMembers,
            bool verbose,
            string? limitToAwsServicePrefix,
            bool noPruneUnrelatedNodes,
            bool noIdentities
        )
        {
            // Analyze policy documents
            Console.Error.WriteLine("Analyzing managed policy contents... ");
            var policyAnalyses = new Dictionary<PolicyArn, PolicyAnalyzerResult>();
            foreach (var p in awsPolicies)
            {
                var result = PolicyAnalyzer.Analyze(p.Arn, Uri.UnescapeDataString(p.PolicyVersionList.Single(v => v.VersionId == p.DefaultVersionId).Document), awsRoles, limitToAwsServicePrefix);
                if (!policyAnalyses.TryAdd(p.Arn, result))
                {
                    // This policy's could have broken across pagination.
                    var currentEntry = policyAnalyses[p.Arn];
                    currentEntry.AssumeRoleTargets.AddRange(result.AssumeRoleTargets);
                    currentEntry.Stanzas.AddRange(result.Stanzas);
                    policyAnalyses[p.Arn] = currentEntry;
                };
            }
            Console.Error.WriteLine($"Analyzing managed policy contents... [\u2713] (count={policyAnalyses.Count})");

            // Analyze role assume policy documents
            var roleAnalyses = new Dictionary<RoleArn, RoleAnalyzerResult>();
            Console.Error.WriteLine("Analyzing assume role policy document contents... ");
            {
                var roleArns = awsRoles.Select(r => r.Arn).ToHashSet();
                foreach (var role in awsRoles)
                {
                    var result = RoleAnalyzer.Analyze(role.AssumeRolePolicyDocument, awsPolicies);
                    roleAnalyses.Add(role.Arn, result);
                }
            }
            Console.Error.WriteLine($"Analyzing assume policy document contents... [\u2713] (count={roleAnalyses.Count})");

            // ######################
            // ### Generate graph ###
            // ######################
            var nodes = new List<Node>();
            var edges = new List<Edge<Node, string>>();

            // Add AWS services to graph
            foreach (var servicePrefix in policyAnalyses.SelectMany(s => s.Value.Stanzas.Select(t => t.Service.ToLowerInvariant())).Distinct())
            {
                if (servicePrefix == null)
                    continue;

                nodes.Add(new Node
                {
                    Name = servicePrefix,
                    Type = NodeType.AwsService,
                    Arn = servicePrefix,
                });
            }

            // Add policies to graph
            foreach (var p in policyAnalyses)
            {
                var policy = awsPolicies.Single(x => string.Compare(x.Arn, p.Key, StringComparison.OrdinalIgnoreCase) == 0);
                if (policy == null)
                    continue;

                var policyNode = new Node
                {
                    Name = policy.PolicyName,
                    Type = NodeType.AwsPolicy,
                    Arn = policy.Arn,
                };

                // Add directed edges from this managed policy to applicable services.
                var ct = 0;
                foreach (var servicePrefix in p.Value.Stanzas.Select(pp => pp.Service).Distinct())
                {
                    var serviceNode = nodes.Single(n =>
                        n.Type.Equals(NodeType.AwsService)
                        && string.Compare(n.Arn, servicePrefix, StringComparison.OrdinalIgnoreCase) == 0);

                    edges.Add(new Edge<Node, string>(policyNode, serviceNode, "references"));
                    ct++;
                }
                if (noPruneUnrelatedNodes || ct > 0)
                    nodes.Add(policyNode);
            }

            // Add groups to graph
            foreach (var g in awsGroups)
            {
                var groupNode = new Node
                {
                    Name = g.GroupName,
                    Type = NodeType.AwsGroup,
                    Arn = g.Arn,
                };

                // Add directed edges from this group to applicable managed policies.
                var ct = 0;
                foreach (var policyArn in g.AttachedManagedPolicies.Select(p => p.PolicyArn))
                {
                    var policyNode = nodes.SingleOrDefault(n =>
                        n.Type.Equals(NodeType.AwsPolicy)
                        && string.Compare(n.Arn, policyArn, StringComparison.OrdinalIgnoreCase) == 0);

                    if (policyNode != default)
                    {
                        edges.Add(new Edge<Node, string>(groupNode, policyNode, "attachedTo"));
                        ct++;
                    }
                }

                // Add directed edges from this group to applicable inline policies.
                foreach (var inlinePolicy in g.GroupPolicyList)
                {
                    var inlinePolicyNode = new Node
                    {
                        Name = $"{g.GroupName}/{inlinePolicy.PolicyName}",
                        Type = NodeType.AwsInlinePolicy,
                        Arn = $"{g.GroupName}/{inlinePolicy.PolicyName}",
                    };

                    var result = PolicyAnalyzer.Analyze(inlinePolicyNode.Arn, Uri.UnescapeDataString(inlinePolicy.PolicyDocument), awsRoles, limitToAwsServicePrefix);

                    // Add directed edges from this policy to applicable services.
                    var ct2 = 0;
                    foreach (var servicePrefix in result.Stanzas.Select(pp => pp.Service).Distinct())
                    {
                        var serviceNode = nodes.SingleOrDefault(n =>
                            n.Type.Equals(NodeType.AwsService)
                            && string.Compare(n.Arn, servicePrefix, StringComparison.OrdinalIgnoreCase) == 0);
                        if (serviceNode != default)
                        {
                            edges.Add(new Edge<Node, string>(inlinePolicyNode, serviceNode, "references"));
                            ct2++;
                        }
                    }

                    if (noPruneUnrelatedNodes || ct2 > 0)
                    {
                        nodes.Add(inlinePolicyNode);
                        edges.Add(new Edge<Node, string>(groupNode, inlinePolicyNode, "attachedTo"));
                        ct++;
                    }
                }

                if (noPruneUnrelatedNodes || ct > 0)
                    nodes.Add(groupNode);
            }

            // Add roles to graph
            foreach (var r in awsRoles)
            {
                var roleNode = new Node
                {
                    Name = r.RoleName,
                    Type = NodeType.AwsRole,
                    Arn = r.Arn,
                };

                // Add directed edges from this role to applicable stand-alone policies.
                var ct = 0;
                foreach (var policyArn in r.AttachedManagedPolicies.Select(p => p.PolicyArn))
                {
                    var policyNode = nodes.SingleOrDefault(n =>
                        n.Type.Equals(NodeType.AwsPolicy)
                        && string.Compare(n.Arn, policyArn, StringComparison.OrdinalIgnoreCase) == 0);

                    if (policyNode != default)
                    {
                        edges.Add(new Edge<Node, string>(roleNode, policyNode, "attachedTo"));
                        ct++;
                    }
                }

                // Add directed edges from this role to applicable inline policies.
                foreach (var inlinePolicy in r.RolePolicyList)
                {
                    var inlinePolicyNode = new Node
                    {
                        Name = $"{r.RoleName}/{inlinePolicy.PolicyName}",
                        Type = NodeType.AwsInlinePolicy,
                        Arn = $"{r.RoleName}/{inlinePolicy.PolicyName}",
                    };

                    var result = PolicyAnalyzer.Analyze(inlinePolicyNode.Arn, Uri.UnescapeDataString(inlinePolicy.PolicyDocument), awsRoles, limitToAwsServicePrefix);

                    // Add directed edges from this policy to applicable services.
                    var ct2 = 0;
                    foreach (var servicePrefix in result.Stanzas.Select(pp => pp.Service).Distinct())
                    {
                        var serviceNode = nodes.SingleOrDefault(n =>
                            n.Type.Equals(NodeType.AwsService)
                            && string.Compare(n.Arn, servicePrefix, StringComparison.OrdinalIgnoreCase) == 0);
                        if (serviceNode != default)
                        {
                            edges.Add(new Edge<Node, string>(inlinePolicyNode, serviceNode, "references"));
                            ct2++;
                        }
                    }

                    if (noPruneUnrelatedNodes || ct2 > 0)
                    {
                        nodes.Add(inlinePolicyNode);
                        edges.Add(new Edge<Node, string>(roleNode, inlinePolicyNode, "attachedTo"));
                        ct++;
                    }
                }

                if (noPruneUnrelatedNodes || ct > 0)
                    nodes.Add(roleNode);
            }

            // Add users to graph
            if (!noIdentities)
                foreach (var u in awsUsers)
                {
                    var userNode = new Node
                    {
                        Name = u.UserName,
                        Type = NodeType.AwsUser,
                        Arn = u.Arn,
                    };

                    // Add directed edges from this user to groups in which the user is a member
                    var ct = 0;
                    foreach (var groupName in u.GroupList)
                    {
                        var groupNode = nodes.SingleOrDefault(n =>
                            n.Type.Equals(NodeType.AwsGroup)
                            && string.Compare(n.Name, groupName, StringComparison.OrdinalIgnoreCase) == 0);

                        if (groupNode != default)
                        {
                            edges.Add(new Edge<Node, string>(userNode, groupNode, "memberOf"));
                            ct++;
                        }
                    }

                    // Add directed edges from this user to applicable stand-alone policies.
                    foreach (var policyArn in u.AttachedManagedPolicies.Select(p => p.PolicyArn))
                    {
                        var policyNode = nodes.SingleOrDefault(n =>
                            n.Type.Equals(NodeType.AwsPolicy)
                            && string.Compare(n.Arn, policyArn, StringComparison.OrdinalIgnoreCase) == 0);

                        if (policyNode != default)
                        {
                            edges.Add(new Edge<Node, string>(userNode, policyNode, "attachedTo"));
                            ct++;
                        }
                    }

                    // Add directed edges from this user to applicable inline policies.
                    foreach (var inlinePolicy in u.UserPolicyList)
                    {
                        var inlinePolicyNode = new Node
                        {
                            Name = $"{u.UserName}/{inlinePolicy.PolicyName}",
                            Type = NodeType.AwsInlinePolicy,
                            Arn = $"{u.UserName}/{inlinePolicy.PolicyName}",
                        };

                        var result = PolicyAnalyzer.Analyze(inlinePolicyNode.Arn, Uri.UnescapeDataString(inlinePolicy.PolicyDocument), awsRoles, limitToAwsServicePrefix);

                        // Add directed edges from this policy to applicable services.
                        var ct2 = 0;
                        foreach (var servicePrefix in result.Stanzas.Select(pp => pp.Service).Distinct())
                        {
                            var serviceNode = nodes.SingleOrDefault(n =>
                                n.Type.Equals(NodeType.AwsService)
                                && string.Compare(n.Arn, servicePrefix, StringComparison.OrdinalIgnoreCase) == 0);
                            if (serviceNode != default)
                            {
                                edges.Add(new Edge<Node, string>(inlinePolicyNode, serviceNode, "references"));
                                ct2++;
                            }
                        }

                        if (noPruneUnrelatedNodes || ct2 > 0)
                        {
                            nodes.Add(inlinePolicyNode);
                            edges.Add(new Edge<Node, string>(userNode, inlinePolicyNode, "attachedTo"));
                            ct++;
                        }
                    }

                    if (noPruneUnrelatedNodes || ct > 0)
                        nodes.Add(userNode);
                }

            // Add policy(attachedTo)role(targeting)role assumption edges to graph
            var roleNodes = nodes.Where(n => n.Type.Equals(NodeType.AwsRole)).ToLookup(r => r.Arn);
            {
                var policyNodes = nodes.Where(n => n.Type.Equals(NodeType.AwsPolicy)).ToLookup(p => p.Arn);

                foreach (var pn in policyNodes)
                {
                    // What roles can this policy assume?
                    var pa = policyAnalyses[pn.Key!];
                    if (pa.AssumeRoleTargets.Count == 0)
                        continue;

                    if (verbose) Console.Error.WriteLine($"{Environment.NewLine}{Environment.NewLine}PolicyArn: {pn.Key}");

                    var rolesThatCanBeAssumed = roleNodes.SelectMany(r => pa.AssumeRoleTargets).Distinct();
                    foreach (var roleThatCanBeAssumed in rolesThatCanBeAssumed)
                    {
                        if (verbose) Console.Error.WriteLine($"\tCan assume: {roleThatCanBeAssumed}");

                        // Can these roles be assumed by principals attached to this policy, though?  If so, they'd be provided for in the trust policy.
                        var rolesWithThisPolicyAttached = edges.FindRolesAttachedTo(pn.Single()).Select(x => x.source).ToArray();
                        if (!rolesWithThisPolicyAttached.Any())
                        {
                            if (verbose) Console.Error.WriteLine($"\t\tBut is not attached to any roles.");
                            continue;
                        }

                        foreach (var roleThatCanAssume in rolesWithThisPolicyAttached)
                        {
                            if (roleThatCanAssume.Arn == null)
                                throw new InvalidOperationException($"Arn is null on {roleThatCanAssume}");
                            if (verbose) Console.Error.WriteLine($"\t\tAnd is attached to role: {roleThatCanAssume.Arn}");

                            var ra = roleAnalyses[roleThatCanAssume.Arn];
                            if (ra.IamRootAllowed)
                            {
                                if (verbose) Console.Error.WriteLine($"\t\t\t...which can be assumed by anything with a policy that permits sts:AssumeRole to it");
                                // Because the role with this policy attached can be assumed by any entity that itself has a grant for sts:AssumeRole to this,
                                // (i.e. is controlled purely by its IAM policy and not a two-way allowance), 
                                foreach (var roleArn in rolesThatCanBeAssumed) {
                                    var targetRole = roleNodes[roleArn].SingleOrDefault();
                                    if (!default(Node).Equals(targetRole))
                                        edges.Add(new Edge<Node, string>(roleThatCanAssume, targetRole, "canAssume"));
                                }
                            }
                            else
                            {
                                foreach (var trustedEntityThatCanAssume in ra.TrustedEntitiesThatCanAssume)
                                {
                                    if (verbose) Console.Error.WriteLine($"\t\t\t...which can be assumed by trusted entity {trustedEntityThatCanAssume}");
                                    var r = awsRoles.SingleOrDefault(r => string.Compare(r.Arn, trustedEntityThatCanAssume, StringComparison.OrdinalIgnoreCase) == 0);
                                    if (r == default)
                                    {
                                        if (verbose) Console.Error.WriteLine($"\t\t\t...which is unresolved (skipping)");
                                        continue;
                                    }

                                    var switch1 = false;
                                    foreach (var policyOnTrustedEntity in r.AttachedManagedPolicies)
                                    {
                                        var ipar = policyAnalyses[policyOnTrustedEntity.PolicyArn];
                                        if (ipar.AssumeRoleTargets.Any(art => string.CompareOrdinal(roleThatCanBeAssumed, art) == 0))
                                        {
                                            if (!switch1 && verbose)
                                                Console.Error.WriteLine($"\t\t\t\t...which has attached policy {policyOnTrustedEntity.PolicyArn}");
                                            switch1 = true;
                                            if (verbose) Console.Error.WriteLine($"\t\t\t\t\t...which CAN assume {roleThatCanBeAssumed}");
                                            edges.Add(new Edge<Node, string>(roleNodes[trustedEntityThatCanAssume].Single(), roleNodes[roleThatCanBeAssumed].Single(), "canAssume"));
                                        }
                                        else
                                        {
                                            //if (verbose) Console.Error.WriteLine($"\t\t\t\t\t...which CANNOT assume {roleThatCanBeAssumed}");
                                        }
                                    }
                                }
                                //throw new NotImplementedException();
                            }
                        }
                    }
                }
            }

            // Add role(can-be-SAMLed-from-Okta-via-GroupMapping) Okta group nodes and related edges to graph
            foreach (var og in oktaGroups.Where(g =>
                !string.IsNullOrWhiteSpace(g.AwsRoleName)))
            {
                var matchingAwsRole = awsRoles.SingleOrDefault(r =>
                    string.Compare(r.RoleName, og.AwsRoleName, StringComparison.OrdinalIgnoreCase) == 0
                    && roleAnalyses[r.Arn].TrustedEntitiesThatCanAssume.Any(te =>
                        awsSamlIdPs.Any(s =>
                            string.Compare(s.Arn, te, StringComparison.OrdinalIgnoreCase) == 0
                            && string.Compare(og.AwsAccountId, Amazon.Arn.Parse(s.Arn).AccountId, StringComparison.OrdinalIgnoreCase) == 0
                        )
                    ));

                if (matchingAwsRole == null)
                    continue;
                var roleNode = roleNodes[matchingAwsRole.Arn].SingleOrDefault();
                if (roleNode == default)
                    continue;

                // Add this Okta group as a node.
                var oktaGroupNode = new Node
                {
                    Name = og.Name!,
                    Type = NodeType.OktaGroup,
                    Arn = og.Id!,
                };
                nodes.Add(oktaGroupNode);
                edges.Add(new Edge<Node, string>(oktaGroupNode, roleNode, "canAssume"));
            }

            // Add applicable Okta users and related edges to graph
            if (!noIdentities)
            {
                var oktaUserNodes = nodes
                    .Where(n => n.Type.Equals(NodeType.OktaGroup))
                    .SelectMany(n => oktaGroupMembers[n.Arn!])
                    .Select(n => n.UserId)
                    .Distinct()
                    .Select(u => oktaUsers.SingleOrDefault(ou => string.Compare(ou.UserId, u, StringComparison.OrdinalIgnoreCase) == 0))
                    .Where(u => u.Login != null) // This is necessary b/c user could have been suspended/deactivated yet still assigned.
                    .Select(u => new Node
                    {
                        Name = u.Login,
                        Type = NodeType.OktaUser,
                        Arn = u.UserId
                    })
                    .ToArray(); // Required so we can modify the collection in the following statement.
                nodes.AddRange(oktaUserNodes);

                // Now the Okta user-group edges.
                {
                    var ounLookup = oktaUserNodes.ToLookup(oun => oun.Arn);
                    foreach (var oktaGroupNode in nodes.Where(n => n.Type.Equals(NodeType.OktaGroup)))
                    {
                        edges.AddRange(oktaGroupMembers[oktaGroupNode.Arn!]
                            .Where(ogm => ogm.UserId != null)
                            .Select(ogm => (ogm.UserId, ounLookup[ogm.UserId!].SingleOrDefault()))
                            .Where(t => t.Item2 != default)
                            .Select(ogm => new Edge<Node, string>(
                                ogm.Item2,
                                oktaGroupNode,
                                "memberOf"
                            )));
                    }
                }

                // Finally, group AwsIamUser and OktaUsers
                {
                    var awsUserNodes = nodes
                        .Where(n => n.Type.Equals(NodeType.AwsUser))
                        .ToArray();

                    var subIdentityNodesProto = oktaUserNodes.Union(awsUserNodes)
                        .GroupBy(x => x.Name.Split('@')[0])
                        .ToDictionary(k => k.Key, v => v.ToArray());

                    var rootIdentityNodes = subIdentityNodesProto
                        .ToDictionary(k => new Node
                        {
                            Arn = k.Key,
                            Type = NodeType.Identity,
                            Name = k.Key
                        }, v => v.Value);
                    nodes.AddRange(rootIdentityNodes.Keys);

                    foreach (var kvp in rootIdentityNodes)
                    {
                        foreach (var sub in kvp.Value)
                        {
                            edges.Add(new Edge<Node, string>(
                                    kvp.Key,
                                    sub,
                                    "is"));
                        }
                    }
                }
            }

            var orphans = nodes
                .Where(n => !edges.Any(e => e.Source == n || e.Destination == n));
            return (nodes.Except(orphans).ToList(), edges);
        }
    }
}