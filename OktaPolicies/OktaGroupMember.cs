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
    public record struct OktaGroupMember : IEquatable<OktaGroupMember>
    {
        public OktaGroupMember() { }

        public OktaGroupMember(OktaGroup g, Okta.Sdk.Model.GroupMember gm)
        {
            GroupId = g.Id;
            UserId = gm.Id;
            Login = gm.Profile.Login;
            FirstName = gm.Profile.FirstName;
            LastName = gm.Profile.LastName;
            ManagerId = gm.Profile.ManagerId;
        }

        public string? GroupId { get; set; } = null;
        public string? UserId { get; set; } = null;
        public string? Login { get; set; } = null;
        public string? FirstName { get; set; } = null;
        public string? LastName { get; set; } = null;
        public string? ManagerId { get; set; } = null;

        public readonly bool Equals(OktaGroupMember? other)
        {
            if (other == null)
                return false;

            return string.Compare(GroupId, other.Value.GroupId, StringComparison.OrdinalIgnoreCase) == 0
                && string.Compare(UserId, other.Value.UserId, StringComparison.OrdinalIgnoreCase) == 0
            ;
        }
    }
}