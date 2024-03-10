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
    public readonly record struct PolicyAnalyzerResult : IComparable, IComparable<PolicyAnalyzerResult>, IEquatable<PolicyAnalyzerResult>
    {
        public readonly PolicyArn PolicyArn { get; init; }

        public readonly List<PolicyStanza> Stanzas { get; init; }

        public readonly List<RoleId> AssumeRoleTargets { get; init; }

        private readonly Func<string>? StringFormatter { get; init; }

        public PolicyStanza FirstWriteStanzaForService(string servicePrefix) =>
            Stanzas
                .Where(s => string.Compare(s.Service, servicePrefix, StringComparison.OrdinalIgnoreCase) == 0)
                .OrderBy(s => s.Write ? 1 : 0)
                .First();

        public bool ReadOnly(string servicePrefix) =>
            !Stanzas
                .Where(s => string.CompareOrdinal(s.Service, servicePrefix) == 0)
                .Any(s => s.Write && !s.Deny);

        public int CompareTo(PolicyAnalyzerResult other)
        {
            if (other == default)
                return -1;
            if (Stanzas.Count != other.Stanzas.Count)
                return Stanzas.Count - other.Stanzas.Count;
            if (AssumeRoleTargets.Count != other.AssumeRoleTargets.Count)
                return AssumeRoleTargets.Count - other.AssumeRoleTargets.Count;

            return string.Compare(PolicyArn, other.PolicyArn, StringComparison.OrdinalIgnoreCase);
        }

        public int CompareTo(object? other)
        {
            if (other == null || GetType() != other.GetType())
                return -1;

            return CompareTo((PolicyAnalyzerResult)other);
        }

        public bool Equals(PolicyAnalyzerResult? other)
        {
            if (other == null)
                return false;
            if (Stanzas.Count != other.Value.Stanzas.Count)
                return false;
            if (AssumeRoleTargets.Count != other.Value.AssumeRoleTargets.Count)
                return false;

            return string.Compare(PolicyArn, other.Value.PolicyArn, StringComparison.OrdinalIgnoreCase) == 0;
        }

        public PolicyAnalyzerResult SubsetForService(string servicePrefix)
        {
            List<PolicyStanza> subsetStanzas = [.. Stanzas.Where(s => string.CompareOrdinal(s.Service, servicePrefix) == 0).OrderBy(s => s.Write ? 1 : 0)];
            return new PolicyAnalyzerResult
            {
                PolicyArn = PolicyArn,
                Stanzas = subsetStanzas,
                AssumeRoleTargets = AssumeRoleTargets,
                StringFormatter = () => subsetStanzas.First().Write ? "controls" : "reads"
            };
        }

        public override string ToString() => 
            (StringFormatter == null) 
                ? "references" 
                : StringFormatter();
    }
}