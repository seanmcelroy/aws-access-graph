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

using AwsAccessGraph.AwsPolicies;

namespace AwsAccessGraph
{
    public class PolicyVisitor
    {
        /// <summary>
        /// Add directed edges from a policy's stanzas to applicable service nodes in a graph.
        /// </summary>
        /// <param name="policyAnalyzerResult"></param>
        /// <param name="policyNode">The policy to attach to the service</param>
        /// <param name="nodes">All nodes known so far in the graph</param>
        /// <param name="edges">All edges known so far in the graph</param>
        /// <returns></returns>
        public static int VisitAndAttachPolicyToServices(
            PolicyAnalyzerResult policyAnalyzerResult,
            Node policyNode,
            List<Node> nodes,
            ref List<IEdge<Node>> edges)
        {
            if (policyNode.Type != NodeType.AwsPolicy && policyNode.Type != NodeType.AwsInlinePolicy)
                throw new ArgumentException("Node is not a policy", nameof(policyNode));

            var edgesAdded = 0;
            var distinctServices = policyAnalyzerResult.Stanzas.Select(s => s.Service).Distinct();
            foreach (var distinctService in distinctServices)
            {
                var serviceNode = nodes.SingleOrDefault(n =>
                    n.Type.Equals(NodeType.AwsService)
                    && string.Compare(n.Arn, distinctService, StringComparison.OrdinalIgnoreCase) == 0);
                if (serviceNode != default)
                {
                    edges.Add(new Edge<Node, PolicyAnalyzerResult>(policyNode, serviceNode, policyAnalyzerResult.SubsetForService(distinctService)));
                    edgesAdded++;
                }
            }

            return edgesAdded;
        }
    }
}