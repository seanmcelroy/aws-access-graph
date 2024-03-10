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
    public class Edge<TNode, TEdgeData>(TNode source, TNode destination, TEdgeData edgeData) : IEdge<TNode>, IComparable<IEdge<TNode>>
        where TNode : struct, INode, IComparable<TNode>, IEquatable<TNode>
    {
        public TNode Source { get; } = source;
        public TNode Destination { get; } = destination;
        public TEdgeData EdgeData { get; } = edgeData;
        object IEdge<TNode>.EdgeData { get => EdgeData; }

        public int CompareTo(IEdge<TNode>? other) => other == null
            ? -1
            : Source.CompareTo(other.Source) +
                Destination.CompareTo(other.Destination);

        public override string ToString() => EdgeData?.ToString() ?? $"{Source.Name}->{Destination.Name}";
    }
}