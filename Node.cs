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
    public readonly record struct Node : INode, IComparable<Node>, IEquatable<Node>
    {
        public string Name { get; init; }
        public NodeType Type { get; init; }
        public string Arn { get; init; }

        public int CompareTo(Node other)
        {
            if (Arn == null || other.Arn == null)
                return Name.CompareTo(other.Name);
            return Arn.CompareTo(other.Arn);
        }

        public int CompareTo(INode? other)
        {
            if (other == null || GetType() != other.GetType())
                return -1;

            return CompareTo((Node)other);
        }

        public bool Equals(Node? other)
        {
            if (other == null)
                return false;

            return string.Compare(Name, other.Value.Name, StringComparison.OrdinalIgnoreCase) == 0
                && Type.Equals(other.Value.Type)
                && string.Compare(Arn, other.Value.Arn, StringComparison.OrdinalIgnoreCase) == 0
            ;
        }

        public bool Equals(INode? other)
        {
            if (other == null || GetType() != other.GetType())
                return false;

            return string.Compare(Name, other.Name, StringComparison.OrdinalIgnoreCase) == 0;
        }

        public override int GetHashCode() => Name.GetHashCode() + Type.GetHashCode() + Arn.GetHashCode();
    }
}