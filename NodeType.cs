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
    public enum NodeType 
    {
        AwsService,
        AwsPolicy,
        AwsInlinePolicy,
        AwsGroup,
        AwsRole,
        AwsUser,
        OktaGroup,
        OktaUser,
        IdentityPrincipal,
        AwsPermissionSet,
        AwsIdentityStoreUser,
        AwsIdentityStoreGroup,
        AwsResource,
    }
}