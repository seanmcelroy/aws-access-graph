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

using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace AwsAccessGraph.OktaPolicies
{
    public record struct OktaGroup : IEquatable<OktaGroup>
    {
        private string? _name = null;

        public OktaGroup() { }

        public OktaGroup(Okta.Sdk.Model.Group g)
        {
            this.Id = g.Id;
            this.Name = g.Profile.Name;
        }

        public string? Id { get; set; } = null;
        public string? Name
        {
            get { return this._name; }
            set
            {
                this._name = value;
                if (value == null)
                    return;

                var m = Regex.Match(value, "aws_(?<accountid>\\d+)_(?<role>[a-zA-Z0-9+=,.@\\-_]+)");
                if (!m.Success)
                    return;

                this.AwsAccountId = m.Groups["accountid"].Value;
                this.AwsRoleName = m.Groups["role"].Value;
            }
        }

        // AWS-specific items
        [JsonIgnore]
        public string? AwsAccountId { get; set; } = null;
        [JsonIgnore]
        public string? AwsRoleName { get; set; } = null;

        public bool Equals(OktaGroup? other)
        {
            if (other == null)
                return false;

            return string.Compare(this.Id, other.Value.Id, StringComparison.OrdinalIgnoreCase) == 0;
        }
    }
}