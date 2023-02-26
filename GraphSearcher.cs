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
            var result = nodes.Single(n => string.Compare(n.Name, serviceName, StringComparison.OrdinalIgnoreCase) == 0
                && n.Type.Equals(NodeType.AwsService));

            if (default(Node).Equals(result))
                throw new InvalidOperationException();

            return result;
        }

        public static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindGroupsAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            return edges.FindNodesAttachedTo(target, new List<Edge<Node, string>>(), NodeType.AwsGroup);
        }

        public static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindRolesAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            return edges.FindNodesAttachedTo(target, new List<Edge<Node, string>>(), NodeType.AwsRole);
        }

        public static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindUsersAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target)
        {
            return edges.FindNodesAttachedTo(target, new List<Edge<Node, string>>(), NodeType.Identity);
        }

        private static IEnumerable<(Node source, IEnumerable<Edge<Node, string>> path)> FindNodesAttachedTo(
            this IEnumerable<Edge<Node, string>> edges,
            Node target,
            IEnumerable<Edge<Node, string>> path,
            NodeType sourceNodeType)
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

                if (dt.Source.Type.Equals(sourceNodeType))
                {
                    yield return (dt.Source, pathArray);
                }
                else
                {
                    foreach (var n in edges.FindNodesAttachedTo(dt.Source, pathArray, sourceNodeType))
                    {
                        yield return n;
                    }
                }
            }
        }
    }
}