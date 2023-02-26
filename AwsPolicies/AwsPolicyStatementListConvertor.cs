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
    public class AwsPolicyStatementListConvertor : JsonConverter<AwsPolicyStatementList>
    {
        public override AwsPolicyStatementList? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            // This could be a single statements, not in an array.
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                var statement = JsonSerializer.Deserialize<AwsPolicyStatement>(ref reader, options);
                return new AwsPolicyStatementList(statement);
            }

            // Or it could be an array of statements.
            if (reader.TokenType == JsonTokenType.StartArray)
            {
                var result = new AwsPolicyStatementList();
                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndArray)
                        return result;

                    if (reader.TokenType != JsonTokenType.StartObject)
                        throw new JsonException();

                    var statement = JsonSerializer.Deserialize<AwsPolicyStatement>(ref reader, options);
                    result.Add(statement);
                };

            }

            throw new JsonException();
        }

        public override void Write(Utf8JsonWriter writer, AwsPolicyStatementList value, JsonSerializerOptions options) => throw new NotImplementedException();
    }
}