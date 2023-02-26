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

namespace AwsAccessGraph.AwsPolicies
{
    public readonly record struct AwsPolicyStatement
    {
        public readonly string? Sid { get; init; }

        [JsonConverter(typeof(AwsPolicyStatementPrincipalMapConvertor))]
        public readonly AwsPolicyStatementPrincipalMap? Principal { get; init ; }

        [JsonConverter(typeof(AwsPolicyStatementPrincipalMapConvertor))]
        public readonly AwsPolicyStatementPrincipalMap? NotPrincipal { get; init ; }

        public readonly string Effect { get; init; }

        [JsonConverter(typeof(AwsPolicyStatementActionListConvertor))]
        public readonly AwsPolicyStatementActionList Action { get; init ; }

        [JsonConverter(typeof(AwsPolicyStatementActionListConvertor))]
        public readonly AwsPolicyStatementActionList NotAction { get; init ; }

        [JsonConverter(typeof(AwsPolicyStatementResourceListConvertor))]
        public readonly AwsPolicyStatementResourceList Resource { get; init ; }

        [JsonConverter(typeof(AwsPolicyStatementResourceListConvertor))]
        public readonly AwsPolicyStatementResourceList NotResource { get; init ; }
    }
}