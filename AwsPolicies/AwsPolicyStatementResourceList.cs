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

namespace AwsAccessGraph.AwsPolicies
{
    public class AwsPolicyStatementResourceList : List<string>, IEquatable<AwsPolicyStatementResourceList>
    {
        public bool IsAny { get; private init; }

        public static readonly AwsPolicyStatementResourceList ANY = new()
        {
            IsAny = true
        };

        internal AwsPolicyStatementResourceList() : base()
        {
        }

        public AwsPolicyStatementResourceList(string resource) : this(new[] { resource })
        {
            if (string.CompareOrdinal(resource, "*") == 0)
                throw new ArgumentException($"Use {nameof(AwsPolicyStatementResourceList)}.{nameof(ANY)} instead of specifying an asterisk!", nameof(resource));
        }

        public AwsPolicyStatementResourceList(IEnumerable<string> resources) : base(resources)
        {
        }

        public override bool Equals(object? obj)
        {
            if (obj == null || GetType() != obj.GetType())
            {
                return false;
            }

            return this.Equals((AwsPolicyStatementResourceList)obj);
        }

        // override object.GetHashCode
        public override int GetHashCode()
        {
            if (IsAny)
                return int.MinValue;
            return base.GetHashCode();
        }

        public bool Equals(AwsPolicyStatementResourceList? other)
        {
            if (other == null)
                return false;
            if (this.Count != other.Count)
                return false;
            if (this.Count == 1
                && this.IsAny
                && other.IsAny)
                return true;

            return base.Equals(other);
        }
    }
}