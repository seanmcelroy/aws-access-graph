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
    public readonly record struct Node : IComparable<Node>, IEquatable<Node>
    {
        public string Name { get; init; }
        public NodeType Type { get; init; }
        public string? Arn { get; init; }

        public int CompareTo(Node other)
        {
            if (Arn == null || other.Arn == null)
                return Name.CompareTo(other.Name);
            return Arn.CompareTo(other.Arn);
        }

        public bool Equals(Node? other)
        {
            if (other == null)
                return false;

            return string.Compare(this.Name, other.Value.Name, StringComparison.OrdinalIgnoreCase) == 0
                && this.Type.Equals(other.Value.Type)
                && string.Compare(this.Arn, other.Value.Arn, StringComparison.OrdinalIgnoreCase) == 0
            ;
        }
    }
}