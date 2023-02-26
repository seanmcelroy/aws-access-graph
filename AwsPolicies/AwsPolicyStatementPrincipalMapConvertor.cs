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

using System.Text.Json;
using System.Text.Json.Serialization;

namespace AwsAccessGraph.AwsPolicies
{
    public class AwsPolicyStatementPrincipalMapConvertor : JsonConverter<AwsPolicyStatementPrincipalMap>
    {
        public override AwsPolicyStatementPrincipalMap? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            // This could simply be "*" for any principal.
            if (reader.TokenType == JsonTokenType.String)
            {
                var val = reader.GetString();
                if (string.IsNullOrEmpty(val))
                    throw new JsonException("A principal_block must be a * or a principal_map");
                if (string.CompareOrdinal(val, "*") == 0)
                    return AwsPolicyStatementPrincipalMap.ANY;
                throw new JsonException("A principal_block must be a * or a principal_map");
            }

            if (reader.TokenType != JsonTokenType.StartObject)
                throw new JsonException("A principal_block must be a * or a principal_map");

            var result = new AwsPolicyStatementPrincipalMap();

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                    return result;

                if (reader.TokenType != JsonTokenType.PropertyName)
                    throw new JsonException("A principal_map_entry must begin with a property name");

                var key = reader.GetString();
                if (string.IsNullOrEmpty(key))
                    throw new JsonException("Key for principal_map_entry is not specified");
                if (string.Compare(key, "AWS", StringComparison.OrdinalIgnoreCase) != 0
                    && string.Compare(key, "Federated", StringComparison.OrdinalIgnoreCase) != 0
                    && string.Compare(key, "Service", StringComparison.OrdinalIgnoreCase) != 0
                    && string.Compare(key, "CanonicalUser", StringComparison.OrdinalIgnoreCase) != 0)
                    throw new JsonException($"A principal_map_entry must be keyed as AWS, Federated, Service or CanonicalUser, but found '{key}'.");

                // This could be a single principal_id_string or an array of them.
                reader.Read();

                if (reader.TokenType == JsonTokenType.String)
                {
                    var arn = reader.GetString();
                    if (!string.IsNullOrEmpty(arn))
                        result.Add(key, new List<SomeArn>() { arn });
                    continue;
                }

                if (reader.TokenType != JsonTokenType.StartArray)
                    throw new JsonException("Expected start of a principal_map_entry value, an array of principal_id_string's.");

                var arns = new List<SomeArn>();

                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndArray)
                        break;
                    if (reader.TokenType != JsonTokenType.String)
                        throw new JsonException("Expected either the end of principal_id_string array or another principal_id_string.");

                    var arn = reader.GetString();
                    if (!string.IsNullOrEmpty(arn))
                        arns.Add(arn);
                }
                result.Add(key, arns);
            }

            throw new JsonException();
        }

        public override void Write(Utf8JsonWriter writer, AwsPolicyStatementPrincipalMap value, JsonSerializerOptions options) => throw new NotImplementedException();
    }
}