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

        public static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindGroupsAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            return edges.FindAncestors(target, new List<Edge<Node, string>>(), NodeType.AwsGroup);
        }

        public static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindRolesAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            return edges.FindAncestors(target, new List<Edge<Node, string>>(), NodeType.AwsRole);
        }

        public static IEnumerable<(Node service, IEnumerable<Edge<Node, string>> path)> FindServicesAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            return edges.FindDescendants(target, new List<Edge<Node, string>>(), NodeType.AwsService);
        }

        public static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindIdentityGroupsAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            if (edges.FindAncestors(target, new List<Edge<Node, string>>(), NodeType.OktaGroup).Any())
                return edges.FindAncestors(target, new List<Edge<Node, string>>(), NodeType.OktaGroup);
            else
                return edges.FindAncestors(target, new List<Edge<Node, string>>(), NodeType.AwsGroup);
        }

        public static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindIdentityPrincipalsAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            return edges.FindAncestors(target, new List<Edge<Node, string>>(), NodeType.IdentityPrincipal);
        }

        private static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindAncestors(
            this IEnumerable<Edge<Node, string>> edges,
            Node target,
            IEnumerable<Edge<Node, string>> path,
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
                var pathArray = pathCount == 0 ? (new[] { default(Edge<Node, string>) }) : new Edge<Node, string>[pathCount + 1];
                if (pathCount > 0)
                    Array.Copy(path.ToArray(), 0, pathArray, 1, pathCount);
                pathArray[0] = dt;

                if (dt.Source.Type.Equals(ancestorNodeType))
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

        private static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindDescendants(
            this IEnumerable<Edge<Node, string>> edges,
            Node target,
            IEnumerable<Edge<Node, string>> path,
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
                var pathArray = pathCount == 0 ? (new[] { default(Edge<Node, string>) }) : new Edge<Node, string>[pathCount + 1];
                if (pathCount > 0)
                    Array.Copy(path.ToArray(), 0, pathArray, 1, pathCount);
                pathArray[0] = st;

                if (st.Destination.Type.Equals(descendentNodeType))
                {
                    yield return (st.Destination, pathArray);
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