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
    public class AwsPolicyStatementPrincipalMap : Dictionary<string, List<SomeArn>>, IEquatable<AwsPolicyStatementPrincipalMap>
    {
        public bool IsAny {get; private init;}

        public static readonly AwsPolicyStatementPrincipalMap ANY = new() {
            IsAny = true
        };

        internal AwsPolicyStatementPrincipalMap() : base()
        {
        }

        public AwsPolicyStatementPrincipalMap(IDictionary<string, List<SomeArn>> dictionary) : base(dictionary)
        {
        }

        public AwsPolicyStatementPrincipalMap(IEnumerable<KeyValuePair<string, List<SomeArn>>> collection) : base(collection)
        {
        }

        public override bool Equals(object? obj)
        {
            if (obj == null || GetType() != obj.GetType())
            {
                return false;
            }

            return this.Equals((AwsPolicyStatementPrincipalMap)obj);
        }

        // override object.GetHashCode
        public override int GetHashCode()
        {
            if (IsAny)
                return int.MinValue;
            return base.GetHashCode();
        }

        public bool Equals(AwsPolicyStatementPrincipalMap? other)
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