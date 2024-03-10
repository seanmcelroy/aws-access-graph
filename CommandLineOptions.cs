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

using CommandLine;

namespace AwsAccessGraph
{
    public class CommandLineOptions
    {
        [Value(index: 0, MetaName = "Service", Required = false, Default = "ec2", HelpText = "AWS service prefix for which to analyze authorizations.")]
        public string AwsServicePrefix { get; set; } = "ec2";

        [Value(index: 1, MetaName = "DB Path", Required = false, Default = "./db", HelpText = "Path to cache API results for offline processing.")]
        public string DbPath { get; set; } = "./db";

        [Value(index: 2, MetaName = "Output Path", Required = false, Default = "./output", HelpText = "Path to cache API results for offline processing.")]
        public string OutputPath { get; set; } = "./output";

        [Value(index: 3, MetaName = "Config Path", Required = false, Default = "./conf", HelpText = "Path to find optional configuration files like IGNORE.csv.")]
        public string ConfigPath { get; set; } = "./conf";

        [Option("aws-profile", Required = false, HelpText = "If specified, the profile name from the AWS config file to use to obtain AWS credentials.  If a profile is specified aws-access-key-id, aws-secret-key, aws-session-token, and aws-account-id arguments are ignored if provided.")]
        public string? AwsProfileName { get; set; }

        [Option("aws-access-key-id", Required = false, HelpText = "If specified, the AWS Access Key ID to authenticate to the AWS API.  If this is not specified but a value is present in the environment variable AWS_ACCESS_KEY_ID, that value will be used instead.  If that is not specified either, cached AWS policies will be ignored, and this will be read programmatically using STS get-caller-identity from the supplied credentials.  This value usually begins with AKIA or ASIA")]
        public string? AwsAccessKeyId { get; set; }

        [Option("aws-secret-key", Required = false, HelpText = "If specified, the AWS Secret Access Key to authenticate to the AWS API.  If this is not specified but a value is present in the environment variable AWS_SECRET_ACCESS_KEY, that value will be used instead.  If that is not specified either, cached AWS policies will be ignored, and this will be read programmatically using STS get-caller-identity from the supplied credentials.")]
        public string? AwsSecretAccessKey { get; set; }

        [Option("aws-session-token", Required = false, HelpText = "If specified, the AWS Session Token to authenticate to the AWS API.  If this is not specified but a value is present in the environment variable AWS_SESSION_TOKEN, that value will be used instead.  This is only relevant when a temporary session token is used instead of a static IAM access key.")]
        public string? AwsSessionToken { get; set; }

        [Option("aws-account-id", Required = false, HelpText = "If specified, the account number of the AWS account to analyze.  If this is not specified but a value is present in the environment variable AWS_ACCOUNT_ID, that value will be used instead.  If that is not specified either, cached AWS policies will be ignored, and this will be read programmatically using STS get-caller-identity from the supplied credentials.")]
        public string? AwsAccountId { get; set; }

        [Option("okta-base-url", Required = false, HelpText = "If specified, the URL of the Okta instance to analyze, such as example.okta.com.  If this is not specified but a value is present in the environment variable OKTA_BASE_URL, that value will be used instead.")]
        public string? OktaBaseUrl { get; set; }

        [Option("okta-api-token", Required = false, HelpText = "If specified, the API token of the Okta instance to analyze.  If this is not specified but a value is present in the environment variable OKTA_API_TOKEN, that value will be used instead.")]
        public string? OktaApiToken { get; set; }

        [Option(shortName: 'r', longName: "report", Required = false, HelpText = "Output an authorization text graph to console or standard out, depending on the --no-files setting.  This is default behavior.", Default = true)]
        public bool OutputTextReport { get; set; } = true;

        [Option(shortName: 'd', longName: "dgml", Required = false, HelpText = "Additionally output a DGML graph.")]
        public bool OutputDGML { get; set; } = false;

        [Option(shortName: 'g', longName: "graphviz", Required = false, HelpText = "Additionally output a Graphviz DOT graph.", Default = false)]
        public bool OutputGraphviz { get; set; } = false;

        [Option(longName: "refresh", Required = false, HelpText = "If specified, fresh data will be retrieved from all possible APIs.")]
        public bool Refresh { get; set; } = false;

        [Option(longName: "refresh-aws", Required = false, HelpText = "If specified, fresh data will be retrieved from the AWS API.")]
        public bool RefreshAws { get; set; } = false;

        [Option(longName: "refresh-okta", Required = false, HelpText = "If specified, fresh data will be retrieved from the Okta API.")]
        public bool RefreshOkta { get; set; } = false;

        [Option(longName: "no-files", Required = false, HelpText = "If specified, no files will be written.  All API accesses are not cached and all results are sent to standard output or standard error only.")]
        public bool NoFiles { get; set; } = false;

        [Option(longName: "no-identity", Required = false, HelpText = "If specified, graphs will not include individual principals, and will terminate at the group or role level.  In complex graphs, this can improve readability of DGML or DOT files.")]
        public bool NoIdentities { get; set; } = false;

        [Option(longName: "no-prune", Required = false, HelpText = "If specified, nodes for services that are not the AwsServicePrefix or that are not part of a direct service-to-identity path are included on any output graphs.")]
        public bool NoPrune { get; set; } = false;

        [Option(shortName: 'v', longName: "verbose", Required = false, HelpText = "Produce verbose logs to standard output.")]
        public bool Verbose { get; set; } = false;
    }
}