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

using Amazon.SecurityToken;

namespace AwsAccessGraph
{

    public static class Globals
    {
        private static Lazy<AmazonSecurityTokenServiceClient>? _stsClientFactory;

        public static Lazy<AmazonSecurityTokenServiceClient>? GetStsClientFactory(
            string? awsAccessKeyId,
            string? awsSecretAccessKey,
            string? awsSessionToken
        )
        {
            if (_stsClientFactory == null)
            {
                if ((string.IsNullOrWhiteSpace(awsAccessKeyId)
                        || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                        && string.IsNullOrWhiteSpace(awsSessionToken))
                    return null;

                _stsClientFactory = new Lazy<AmazonSecurityTokenServiceClient>(() =>
                {
                    Console.Error.Write("Getting STS client... ");
                    var sts = new AmazonSecurityTokenServiceClient(awsAccessKeyId, awsSecretAccessKey, awsSessionToken);
                    Console.Error.WriteLine("[\u2713]");
                    return sts;
                });
            }
            return _stsClientFactory;
        }
    }
}