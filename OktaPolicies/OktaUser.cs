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

namespace AwsAccessGraph.OktaPolicies
{
    public record struct OktaUser : IEquatable<OktaUser>
    {
        public OktaUser() { }

        public OktaUser(Okta.Sdk.Model.User u)
        {
            this.UserId = u.Id;
            this.Login = u.Profile.Login;
            this.FirstName = u.Profile.FirstName;
            this.LastName = u.Profile.LastName;
            this.ManagerId = u.Profile.ManagerId;
        }

        public string? UserId { get; set; } = null;
        public string? Login { get; set; } = null;
        public string? FirstName { get; set; } = null;
        public string? LastName { get; set; } = null;
        public string? ManagerId { get; set; } = null;

        public readonly bool Equals(OktaGroupMember? other)
        {
            if (other == null)
                return false;

            return string.Compare(this.UserId, other.Value.UserId, StringComparison.OrdinalIgnoreCase) == 0
            ;
        }
    }
}