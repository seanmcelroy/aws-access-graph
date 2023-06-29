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
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.SecurityToken;

namespace AwsAccessGraph.AwsPolicies
{
    public static class AwsPolicyLoader
    {
        public static int CachedHours { get; set; } = int.MaxValue;

        private static AmazonIdentityManagementServiceClient? iamClient = null;

        public static async Task<(
            List<GroupDetail> groupList,
            List<ManagedPolicyDetail> policyList,
            List<RoleDetail> roleList,
            List<UserDetail> userList,
            List<SAMLProviderListEntry> awsSamlIdPs
            )> LoadAwsPolicyAsync(
                string? awsAccessKeyId,
                string? awsSecretAccessKey,
                string? awsSessionToken,
                string? awsAccountId,
                string outputDirectory,
                bool forceRefresh,
                bool noFiles,
                CancellationToken cancellationToken)
        {
            var stsClientFactory = new Lazy<AmazonSecurityTokenServiceClient?>(() =>
            {
                Console.Error.Write("Getting STS client... ");

                if (string.IsNullOrWhiteSpace(awsAccessKeyId)
                    || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                {
                    Console.Error.WriteLine("[X]");
                    Console.Error.WriteLine($"No AWS Access Key ID or AWS Secret Access Key was specified.  Aboring STS client creation.");
                    return null;
                }

                var sts = new AmazonSecurityTokenServiceClient(awsAccessKeyId, awsSecretAccessKey, awsSessionToken);
                Console.Error.WriteLine("[\u2713]");

                return sts;
            });

            if (string.IsNullOrWhiteSpace(awsAccountId))
            {
                var stsClient = stsClientFactory.Value;
                if (stsClient == null)
                {
                    Console.Error.WriteLine($"Because no AWS Access Key ID or AWS Secret Access Key was specified and no AWS Account ID was provided, processing cannot continue.");
                    System.Environment.Exit((int)Constants.ExitCodes.AwsAccountIdMissing);
                    return default;
                }
                var identity = await stsClient.GetCallerIdentityAsync(new Amazon.SecurityToken.Model.GetCallerIdentityRequest(), cancellationToken);
                awsAccountId = identity.Account;
            }
            Console.Error.WriteLine($"Analyzing AWS Account {awsAccountId}");

            var iamClientFactory = new Lazy<AmazonIdentityManagementServiceClient>(() =>
            {
                Console.Error.Write("Getting IAM client... ");
                var iam = new Amazon.IdentityManagement.AmazonIdentityManagementServiceClient(
                    awsAccessKeyId,
                    awsSecretAccessKey,
                    awsSessionToken);
                Console.Error.WriteLine("[\u2713]");

                return iam;
            });

            // ############################################
            // ### Account Authorization Details Report ###
            // ############################################
            List<GroupDetail>? groupList = null;
            List<ManagedPolicyDetail>? policyList = null;
            List<RoleDetail>? roleList = null;
            List<UserDetail>? userList = null;
            List<SAMLProviderListEntry>? samlIdpList = null;
            {
                Console.Write("Enumerating Account Authorization Details... ");
                var groupListPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-group-list.json");
                var policyListPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-policy-list.json");
                var roleListPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-role-list.json");
                var userListPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-user-list.json");
                var samlIdpListPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-saml-idp-list.json");

                if (!forceRefresh
                   && File.Exists(groupListPath)
                   && (DateTime.UtcNow - File.GetLastWriteTimeUtc(groupListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(groupListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            groupList = await JsonSerializer.DeserializeAsync<List<GroupDetail>>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {groupList!.Count} groups read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from AWS group cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        groupList = null;
                    }
                }

                if (!forceRefresh
                    && File.Exists(policyListPath)
                    && (DateTime.UtcNow - File.GetLastWriteTimeUtc(policyListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(policyListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            policyList = await JsonSerializer.DeserializeAsync<List<ManagedPolicyDetail>>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {policyList!.Count} policies read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from AWS policy cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        policyList = null;
                    }
                }

                if (!forceRefresh
                    && File.Exists(roleListPath)
                    && (DateTime.UtcNow - File.GetLastWriteTimeUtc(roleListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(roleListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            roleList = await JsonSerializer.DeserializeAsync<List<RoleDetail>>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {roleList!.Count} roles read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from AWS roles cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        roleList = null;
                    }
                }

                if (!forceRefresh
                    && File.Exists(userListPath)
                    && (DateTime.UtcNow - File.GetLastWriteTimeUtc(userListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(userListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            userList = await JsonSerializer.DeserializeAsync<List<UserDetail>>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {userList!.Count} users read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from AWS users cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        userList = null;
                    }
                }

                if (groupList == null
                    || policyList == null
                    || roleList == null
                    || userList == null)
                {
                    groupList ??= new List<GroupDetail>();
                    policyList ??= new List<ManagedPolicyDetail>();
                    roleList ??= new List<RoleDetail>();
                    userList ??= new List<UserDetail>();
                    var more = false;
                    string? marker = null;
                    iamClient = iamClient ?? iamClientFactory.Value;
                    do
                    {
                        var response = await iamClient.GetAccountAuthorizationDetailsAsync(new GetAccountAuthorizationDetailsRequest
                        {
                            Marker = marker,
                        }, cancellationToken);
                        if (response == null)
                            break;
                        more = response.IsTruncated;
                        marker = response.Marker;

                        groupList.AddRange(response.GroupDetailList.Except(groupList));
                        policyList.AddRange(response.Policies.Except(policyList));
                        roleList.AddRange(response.RoleDetailList.Except(roleList));
                        userList.AddRange(response.UserDetailList.Except(userList));

                    } while (more && !cancellationToken.IsCancellationRequested);
                    Console.Error.WriteLine($"[\u2713] {groupList.Count} groups, {policyList.Count} policies, {roleList.Count} roles, {userList.Count} users read from AWS API.");
                    if (!noFiles
                        && (groupList.Any() || policyList.Any() || roleList.Any() || userList.Any()))
                    {
                        if (!Directory.Exists(outputDirectory))
                            Directory.CreateDirectory(outputDirectory);

                        await File.WriteAllTextAsync(groupListPath, JsonSerializer.Serialize(groupList), cancellationToken);
                        await File.WriteAllTextAsync(policyListPath, JsonSerializer.Serialize(policyList), cancellationToken);
                        await File.WriteAllTextAsync(roleListPath, JsonSerializer.Serialize(roleList), cancellationToken);
                        await File.WriteAllTextAsync(userListPath, JsonSerializer.Serialize(userList), cancellationToken);
                    }
                }

                // SAML providers, separate call.
                if (!forceRefresh
                    && File.Exists(samlIdpListPath)
                    && (DateTime.UtcNow - File.GetLastWriteTimeUtc(samlIdpListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(samlIdpListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            samlIdpList = await JsonSerializer.DeserializeAsync<List<SAMLProviderListEntry>>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {samlIdpList!.Count} SAML providers read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from AWS SAML IdP cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        userList = null;
                    }
                }

                if (samlIdpList == null)
                {
                    samlIdpList ??= new List<SAMLProviderListEntry>();
                    iamClient = iamClient ?? iamClientFactory.Value;
                    var response = await iamClient.ListSAMLProvidersAsync(new ListSAMLProvidersRequest(), cancellationToken);
                    samlIdpList.AddRange(response.SAMLProviderList);

                    Console.Error.WriteLine($"[\u2713] {samlIdpList.Count} SAML providers read from AWS API.");
                    if (!noFiles && samlIdpList.Any())
                    {
                        if (!Directory.Exists(outputDirectory))
                            Directory.CreateDirectory(outputDirectory);
                        await File.WriteAllTextAsync(samlIdpListPath, JsonSerializer.Serialize(samlIdpList), cancellationToken);
                    }
                }

                // However, we will prune our memory copy to only care about policies with attachments.
                //policyList = policyList.Where(p => p.AttachmentCount > 0).ToList();
            }

            return (groupList!, policyList!, roleList!, userList!, samlIdpList!);
        }

        public static async Task<
            Dictionary<string, EntityDetails[]>
            > LoadAwsLastAccessedReportsAsync(
                string? awsAccessKeyId,
                string? awsSecretAccessKey,
                string? awsSessionToken,
                string? awsAccountId,
                string outputDirectory,
                bool forceRefresh,
                bool noFiles,
                List<RoleDetail> roleList,
                Dictionary<string, Node[]> policyServices,
                CancellationToken cancellationToken)
        {
            // #################################################
            // ### GenerateServiceLastAccessedDetails Report ###
            // #################################################
            var iamClientFactory = new Lazy<AmazonIdentityManagementServiceClient>(() =>
                        {
                            Console.Error.Write("Getting IAM client... ");
                            var iam = new Amazon.IdentityManagement.AmazonIdentityManagementServiceClient(
                                awsAccessKeyId,
                                awsSecretAccessKey,
                                awsSessionToken);
                            Console.Error.WriteLine("[\u2713]");

                            return iam;
                        });

            Console.Write("Enumerating Service Last Action action details... ");

            // Get this for each role.
            var roleJobIds = new Queue<(string RoleId, string JobId)>(roleList.Count);
            foreach (var role in roleList)
            {
                var roleActionDetailsPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-role-{role.RoleId}-service-last-action-report.json");
                if (!forceRefresh
                   && File.Exists(roleActionDetailsPath)
                   && (DateTime.UtcNow - File.GetLastWriteTimeUtc(roleActionDetailsPath)).TotalHours < CachedHours)
                {
                    iamClient = iamClient ?? iamClientFactory.Value;
                    do
                    {
                        var response = await iamClient.GenerateServiceLastAccessedDetailsAsync(new GenerateServiceLastAccessedDetailsRequest
                        {
                            Arn = role.Arn,
                            Granularity = AccessAdvisorUsageGranularityType.ACTION_LEVEL
                        }, cancellationToken);
                        if (response == null || response.HttpStatusCode != System.Net.HttpStatusCode.OK)
                            break;

                        roleJobIds.Enqueue((role.RoleId, response.JobId));
                    } while (!cancellationToken.IsCancellationRequested);
                }
            }

            Dictionary<string, EntityDetails[]> roleEntityDetailList = new();

            while (roleJobIds.Count > 0)
            {
                var nextRole = roleJobIds.Peek();
                var roleActionDetailsPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-role-{nextRole.RoleId}-service-last-action-report.json");
                var more = false;
                string? marker = null;
                iamClient = iamClient ?? iamClientFactory.Value;

                var entitiesDetailsList = new List<EntityDetails>();
                do
                {
                    var response = await iamClient.GetServiceLastAccessedDetailsWithEntitiesAsync(new GetServiceLastAccessedDetailsWithEntitiesRequest
                    {
                        JobId = nextRole.JobId,
                        Marker = marker,
                    }, cancellationToken);
                    if (response == null)
                        break;

                    if (response.JobStatus == JobStatusType.FAILED)
                    {
                        Console.Error.WriteLine($"Error reading GetServiceLastAccessedDetailsWithEntitiesAsync for Job {nextRole.JobId} for role {nextRole.RoleId}: {response.Error}.");
                        break;
                    }
                    if (response.JobStatus == JobStatusType.IN_PROGRESS)
                    {
                        Console.Error.WriteLine($"Still waiting on GetServiceLastAccessedDetailsWithEntitiesAsync for Job {nextRole.JobId} for role {nextRole.RoleId}: polling again in 10 seconds.");
                        Thread.Sleep(10);
                        continue;
                    }

                    // Job completed:
                    more = response.IsTruncated;
                    marker = response.Marker;

                    entitiesDetailsList.AddRange(response.EntityDetailsList);

                } while (more && !cancellationToken.IsCancellationRequested);

                roleEntityDetailList.Add(nextRole.RoleId, entitiesDetailsList.ToArray());
                roleJobIds.Dequeue();
            }

            return roleEntityDetailList;
        }
    }
}