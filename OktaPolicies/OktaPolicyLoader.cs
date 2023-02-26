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
using Okta.Sdk.Api;
using Okta.Sdk.Client;

namespace AwsAccessGraph.OktaPolicies
{
    public static class OktaPolicyLoader
    {
        public static int CachedHours { get; set; } = int.MaxValue;

        public static async Task<(
            OktaGroup[] groupList,
            OktaUser[] userList,
            Dictionary<OktaGroupId, OktaGroupMember[]> awsGroupUsers
            )> LoadOktaPolicyAsync(
                string oktaDomain,
                string oktaApiToken,
                string outputDirectory,
                bool forceRefresh,
                bool noFiles,
                CancellationToken cancellationToken = default)
        {
            // ###################
            // ### Okta Groups ###
            // ###################
            var oktaGroupClient = new Lazy<GroupApi>(() =>
                {
                    Console.Write("Getting Okta group API client... ");

                    var config = new Configuration
                    {
                        OktaDomain = $"https://{oktaDomain}",
                        Token = oktaApiToken
                    };
                    var groupApi = new GroupApi(config);
                    return groupApi;
                });

            OktaGroup[]? groupList = null;
            {
                var groupListPath = Path.Combine(outputDirectory, $"okta-{oktaDomain}-group-list.json");

                if (!forceRefresh
                       && File.Exists(groupListPath)
                       && (DateTime.UtcNow - File.GetLastWriteTimeUtc(groupListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(groupListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            groupList = await JsonSerializer.DeserializeAsync<OktaGroup[]>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {groupList!.Length} groups read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from Okta group cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        groupList = null;
                    }
                }

                if (groupList == null)
                {
                    var rawGroupList = await oktaGroupClient.Value.ListGroups(cancellationToken: cancellationToken).ToArrayAsync(cancellationToken);
                    groupList = rawGroupList.Select(r => new OktaGroup(r)).ToArray();
                    Console.Error.WriteLine($"[\u2713] {groupList.Length} groups read from Okta API.");
                    if (!noFiles && groupList.Any())
                    {
                        if (!Directory.Exists(outputDirectory))
                            Directory.CreateDirectory(outputDirectory);
                        await File.WriteAllTextAsync(groupListPath, JsonSerializer.Serialize(groupList!), cancellationToken);
                    }
                }
            }

            // ##################
            // ### Okta Users ###
            // ##################
            var oktaUserClient = new Lazy<UserApi>(() =>
                {
                    Console.Write("Getting Okta user API client... ");

                    var config = new Configuration
                    {
                        OktaDomain = $"https://{oktaDomain}",
                        Token = oktaApiToken
                    };
                    var userApi = new UserApi(config);
                    return userApi;
                });

            OktaUser[]? userList = null;
            {
                var userListPath = Path.Combine(outputDirectory, $"okta-{oktaDomain}-user-list.json");

                if (!forceRefresh
                       && File.Exists(userListPath)
                       && (DateTime.UtcNow - File.GetLastWriteTimeUtc(userListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(userListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            userList = await JsonSerializer.DeserializeAsync<OktaUser[]>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {userList!.Length} users read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from Okta users cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        userList = null;
                    }
                }

                if (userList == null)
                {
                    var rawUserList = await oktaUserClient.Value.ListUsers(cancellationToken: cancellationToken).ToArrayAsync(cancellationToken);
                    userList = rawUserList.Select(r => new OktaUser(r)).ToArray();
                    Console.Error.WriteLine($"[\u2713] {userList.Length} users read from Okta API.");
                    if (!noFiles && userList.Any())
                    {
                        if (!Directory.Exists(outputDirectory))
                            Directory.CreateDirectory(outputDirectory);
                        await File.WriteAllTextAsync(userListPath, JsonSerializer.Serialize(userList), cancellationToken);
                    }
                }
            }

            // Members of Okta-AWS groups
            Dictionary<OktaGroupId, OktaGroupMember[]>? awsGroupUsers = null;
            {
                var groupMembersListPath = Path.Combine(outputDirectory, $"okta-{oktaDomain}-membership-list.json");

                if (!forceRefresh
                    && File.Exists(groupMembersListPath)
                    && (DateTime.UtcNow - File.GetLastWriteTimeUtc(groupMembersListPath)).TotalHours < CachedHours)
                {
                    try
                    {
                        using (var fs = new FileStream(groupMembersListPath, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                        {
                            awsGroupUsers = await JsonSerializer.DeserializeAsync<Dictionary<OktaGroupId, OktaGroupMember[]>>(fs, cancellationToken: cancellationToken);
                        }
                        Console.Error.WriteLine($"[\u2713] {awsGroupUsers!.Count()} AWS-related groups and {awsGroupUsers!.Sum(x => x.Value.Length)} group members read from cache.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error reading from Okta group-users cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}, trying API... ");
                        userList = null;
                    }
                }

                if (awsGroupUsers == null)
                {
                    awsGroupUsers = new Dictionary<OktaGroupId, OktaGroupMember[]>();
                    foreach (var group in groupList.Where(g => g.Name!.StartsWith("aws", StringComparison.OrdinalIgnoreCase)))
                    {
                        if (string.IsNullOrWhiteSpace(group.Id))
                            throw new InvalidOperationException($"Group ID is not set on: {group}");

                        var groupUsers = await oktaGroupClient.Value.ListGroupUsers(group.Id, cancellationToken: cancellationToken).ToArrayAsync(cancellationToken);
                        awsGroupUsers.Add(
                            group.Id,
                            groupUsers.Select(gu => new OktaGroupMember(group, gu)).ToArray());
                    }
                    Console.Error.WriteLine($"[\u2713] {awsGroupUsers.Count()} AWS-related groups and {awsGroupUsers.Sum(x => x.Value.Length)} group members read from Okta API.");
                    if (!noFiles && awsGroupUsers.Any())
                    {
                        if (!Directory.Exists(outputDirectory))
                            Directory.CreateDirectory(outputDirectory);
                        await File.WriteAllTextAsync(groupMembersListPath, JsonSerializer.Serialize(awsGroupUsers), cancellationToken);
                    }
                }
            }

            return (groupList, userList, awsGroupUsers);
        }
    }
}