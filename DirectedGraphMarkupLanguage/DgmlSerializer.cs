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

using System.Xml.Serialization;

namespace AwsAccessGraph.DirectedGraphMarkupLanguage
{
    public static class DgmlSerializer
    {
        public static void Serialize(Stream stream, List<Node> nodes, List<Edge<Node, string>> edges)
        {
            var dg = new DirectedGraph
            {
                Nodes = nodes.Select(n =>
                {
                    var nodeName = n.Name;
                    if (n.Type.Equals(NodeType.AwsService))
                    {
                        if (!Constants.AwsServicePolicyNames.TryGetValue(n.Name, out string? awsService))
                            nodeName = $"UNKNOWN SERVICE PREFIX {n.Name}";
                    }

                    return new DirectedGraphNode
                    {
                        Id = n.Arn ?? $"{n.Type}:{nodeName}",
                        Label = nodeName,
                        Category = Enum.GetName<NodeType>(n.Type)!
                    };
                }).ToList(),
                Links = edges
                .Select(e => new DirectedGraphLink
                {
                    Source = e.Source.Arn,
                    Target = e.Destination.Arn,
                    Label = e.EdgeData
                }).ToList()
            };

            var writer = new XmlSerializer(typeof(DirectedGraph));
            writer.Serialize(stream, dg);
        }

        public static void Write(string dgmlPath, List<Node> nodes, List<Edge<Node, string>> edges)
        {
            using var fs = new FileStream(dgmlPath, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.None });
            Serialize(fs, nodes, edges);
        }
    }
}