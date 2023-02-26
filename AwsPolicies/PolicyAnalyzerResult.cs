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
    public readonly record struct PolicyAnalyzerResult : IEquatable<PolicyAnalyzerResult>
    {
        public readonly PolicyArn PolicyArn { get; init; }

        public readonly List<PolicyStanza> Stanzas { get; init; }

        public readonly List<RoleId> AssumeRoleTargets { get; init; }

        public bool Equals(PolicyAnalyzerResult? other)
        {
            if (other == null)
                return false;
            if (this.Stanzas.Count != other.Value.Stanzas.Count)
                return false;
            if (this.AssumeRoleTargets.Count != other.Value.AssumeRoleTargets.Count)
                return false;

            return string.Compare(this.PolicyArn, other.Value.PolicyArn, StringComparison.OrdinalIgnoreCase) == 0;
        }
    }
}