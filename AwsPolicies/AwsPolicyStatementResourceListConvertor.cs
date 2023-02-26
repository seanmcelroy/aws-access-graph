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
    public class AwsPolicyStatementResourceListConvertor : JsonConverter<AwsPolicyStatementResourceList>
    {
        public override AwsPolicyStatementResourceList? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            // This could be a single resource, not in an array.
            if (reader.TokenType == JsonTokenType.String)
            {
                var resource = reader.GetString();
                if (string.IsNullOrEmpty(resource))
                    return null;
                if (string.CompareOrdinal(resource, "*") == 0)
                    return AwsPolicyStatementResourceList.ANY;
                return new AwsPolicyStatementResourceList(resource);
            }

            // Or it could be an array.
            if (reader.TokenType == JsonTokenType.StartArray)
            {
                var result = new AwsPolicyStatementResourceList();
                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndArray)
                        return result;

                    if (reader.TokenType == JsonTokenType.String)
                    {
                        var val = reader.GetString();
                        if (!string.IsNullOrEmpty(val))
                            result.Add(val);
                        continue;
                    }

                    throw new JsonException();
                };

            }

            throw new JsonException();
        }

        public override void Write(Utf8JsonWriter writer, AwsPolicyStatementResourceList value, JsonSerializerOptions options) => throw new NotImplementedException();
    }
}