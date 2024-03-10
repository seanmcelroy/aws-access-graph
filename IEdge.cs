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
    public interface IEdge<TNode> : IEdgeInternal<TNode, TNode>
        where TNode : INode, IComparable<TNode>, IEquatable<TNode>
    {
        public object EdgeData { get; }
    }

    public interface IEdgeInternal<out TNode, TNode2> : IComparable<IEdge<TNode2>>
        where TNode : TNode2, INode, IComparable<TNode>, IComparable<TNode2>, IEquatable<TNode>, IEquatable<TNode2>
        where TNode2 : INode, IComparable<TNode2>, IEquatable<TNode2>
    {
        public TNode Source { get; }
        public TNode Destination { get; }
    }
}