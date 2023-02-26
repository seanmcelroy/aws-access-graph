
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

namespace AwsAccessGraph.Graphviz
{
    public static class DotSerializer
    {
        public static async Task SerializeAsync(
            Stream stream,
            IEnumerable<Node> nodes,
            IEnumerable<Edge<Node, string>> edges,
            CancellationToken cancellationToken = default)
        {
            var stmts = new List<string>();

            // Nodes
            foreach (var n in nodes)
            {
                var nodeName = n.Type switch
                {
                    NodeType.AwsPolicy => $"AWS Policy {n.Name}",
                    NodeType.AwsGroup => $"AWS Group {n.Name}",
                    NodeType.AwsRole => $"AWS Role {n.Name}",
                    NodeType.AwsUser => $"AWS IAM User {n.Name}",
                    NodeType.OktaGroup => $"Okta Group {n.Name}",
                    NodeType.OktaUser => $"Okta User {n.Name}",
                    _ => n.Name
                };

                if (n.Type.Equals(NodeType.AwsService))
                {
                    if (!Constants.AwsServicePolicyNames.TryGetValue(n.Name, out string? awsService))
                        nodeName = $"UNKNOWN SERVICE PREFIX {n.Name}";
                }

                if (string.CompareOrdinal(n.Arn, "*") == 0)
                    stmts.Add($"\"{n.Arn!.Replace("*", "EVERYTHING!")}\" [color=red label=\"{nodeName}\", type=\"{n.Type}\"]");
                else if (n.Type == NodeType.Identity)
                    stmts.Add($"\"{n.Arn}\" [color=blue label=\"{nodeName}\", type=\"{n.Type}\"]");
                else if (n.Type == NodeType.AwsUser)
                    stmts.Add($"\"{n.Arn}\" [color=cornflowerblue label=\"{nodeName}\", type=\"{n.Type}\"]");
                else if (n.Type == NodeType.OktaUser)
                    stmts.Add($"\"{n.Arn}\" [color=cyan label=\"{nodeName}\", type=\"{n.Type}\"]");
                else if (n.Type == NodeType.AwsRole)
                    stmts.Add($"\"{n.Arn}\" [color=darkgreen label=\"{nodeName}\", type=\"{n.Type}\"]");
                else if (n.Type == NodeType.AwsGroup)
                    stmts.Add($"\"{n.Arn}\" [color=darkolivegreen label=\"{nodeName}\", type=\"{n.Type}\"]");
                else if (n.Type == NodeType.OktaGroup)
                    stmts.Add($"\"{n.Arn}\" [color=darkolivegreen4 label=\"{nodeName}\", type=\"{n.Type}\"]");
                else if (n.Type == NodeType.AwsService)
                    stmts.Add($"\"{n.Arn}\" [color=crimson label=\"{nodeName}\", type=\"{n.Type}\"]");
                else
                    stmts.Add($"\"{n.Arn}\" [label=\"{nodeName}\", type=\"{n.Type}\"]");
            }

            // Edges
            foreach (var edge in edges)
            {
                if (edge.Source.Type == NodeType.AwsUser)
                    stmts.Add($"\"{edge.Source.Arn}\" -> \"{edge.Destination.Arn}\" [color=cornflowerblue label=\"{edge.EdgeData}\"]");
                else
                    stmts.Add($"\"{edge.Source.Arn}\" -> \"{edge.Destination.Arn}\" [label=\"{edge.EdgeData}\"]");
            }

            var stmt = stmts.Aggregate((c, n) => $"{c};\n\t{n}");


            var sw = new StreamWriter(stream);
            await sw.WriteAsync($"strict digraph aws {{\n\t{stmt}\n}}".AsMemory(), cancellationToken);
            await sw.FlushAsync();
        }

        public static async Task WriteAsync(string dgmlPath, IEnumerable<Node> nodes, IEnumerable<Edge<Node, string>> edges, CancellationToken cancellationToken = default)
        {
            using var fs = new FileStream(dgmlPath, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.None });
            await SerializeAsync(fs, nodes, edges, cancellationToken);
        }
    }
}