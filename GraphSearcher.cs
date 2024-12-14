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

namespace AwsAccessGraph
{
    public static class GraphSearcher
    {
        public static Node FindServiceNode(this IEnumerable<Node> nodes, string serviceName)
        {
            var matchingNodes = nodes.Where(n => string.Compare(n.Name, serviceName, StringComparison.OrdinalIgnoreCase) == 0
                && n.Type.Equals(NodeType.AwsService));

            if (!matchingNodes.Any())
                return default(Node);

            Node result;
            try
            {
                result = matchingNodes.SingleOrDefault();
            }
            catch
            {
                Console.Error.WriteLine($"More than one service node found for '{serviceName}', found {nodes.Count(n => string.Compare(n.Name, serviceName, StringComparison.OrdinalIgnoreCase) == 0 && n.Type.Equals(NodeType.AwsService))}");
                throw;
            }

            return result;
        }

        public static IEnumerable<(Node source, IEnumerable<IEdge<Node>> path)> FindGroupsAttachedTo(
            this IEnumerable<IEdge<Node>> edges,
            Node target)
        {
            return edges.FindAncestors(target, [], NodeType.AwsGroup);
        }

        public static IEnumerable<(Node source, IEnumerable<IEdge<Node>> path)> FindRolesAttachedTo(
            this IEnumerable<IEdge<Node>> edges,
            Node target)
        {
            return edges.FindAncestors(target, [], NodeType.AwsRole);
        }

        public static IEnumerable<(Node service, IEnumerable<IEdge<Node>> path)> FindServicesAttachedTo(
            this IEnumerable<IEdge<Node>> edges,
            Node target)
        {
            return edges.FindDescendants(target, [], NodeType.AwsService);
        }

        public static IEnumerable<(Node source, IEnumerable<IEdge<Node>> path)> FindIdentityGroupsAttachedTo(
            this IEnumerable<IEdge<Node>> edges,
            Node target)
        {
            if (edges.FindAncestors(target, [], NodeType.OktaGroup).Any())
                return edges.FindAncestors(target, [], NodeType.OktaGroup);
            else
                return edges.FindAncestors(target, [], NodeType.AwsGroup);
        }

        public static IEnumerable<(Node source, IEnumerable<IEdge<Node>> path)> FindIdentityPrincipalsAttachedTo(
            this IEnumerable<IEdge<Node>> edges,
            Node target)
        {
            return edges.FindAncestors(target, [], NodeType.IdentityPrincipal);
        }

        private static IEnumerable<(Node source, IEnumerable<IEdge<Node>> path)> FindAncestors(
            this IEnumerable<IEdge<Node>> edges,
            Node target,
            IEnumerable<IEdge<Node>> path,
            NodeType ancestorNodeType)
        {
            // Find everything attached to target whether a group or not
            var destinationOfTarget = edges.Where(e => e.Destination == target);
            foreach (var dt in destinationOfTarget)
            {
                // If this is already in the path, skip so we avoid cycles.
                if (path.Any(p => dt.Source == p.Source))
                    continue;

                var pathCount = path.Count();
                var pathArray = pathCount == 0 ? (new IEdge<Node>[1]) : new IEdge<Node>[pathCount + 1];
                if (pathCount > 0)
                    Array.Copy(path.ToArray(), 0, pathArray, 1, pathCount);
                pathArray[0] = dt;

                if (dt.Source is Node node 
                    && node.Type.Equals(ancestorNodeType)
                    && (target.AccountId == null || string.CompareOrdinal(node.AccountId, target.AccountId) == 0)
                )
                {
                    yield return (dt.Source, pathArray);
                }
                else
                {
                    foreach (var n in edges.FindAncestors(dt.Source, pathArray, ancestorNodeType))
                    {
                        yield return n;
                    }
                }
            }
        }

        private static IEnumerable<(Node source, IEnumerable<IEdge<Node>> path)> FindDescendants(
            this IEnumerable<IEdge<Node>> edges,
            Node target,
            IEnumerable<IEdge<Node>> path,
            NodeType descendentNodeType)
        {
            // Find everything attached to target whether a group or not
            var sourceOfTarget = edges.Where(e => e.Source == target);
            foreach (var st in sourceOfTarget)
            {
                // If this is already in the path, skip so we avoid cycles.
                if (path.Any(p => st.Destination == p.Destination))
                    continue;

                var pathCount = path.Count();
                var pathArray = pathCount == 0 ? new IEdge<Node>[1] : new IEdge<Node>[pathCount + 1];
                if (pathCount > 0)
                    Array.Copy(path.ToArray(), 0, pathArray, 1, pathCount);
                pathArray[0] = st;

                if (st.Destination is Node node && node.Type.Equals(descendentNodeType))
                {
                    yield return (node, pathArray);
                }
                else
                {
                    foreach (var n in edges.FindDescendants(st.Destination, pathArray, descendentNodeType))
                    {
                        yield return n;
                    }
                }
            }
        }
    }
}