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
using Amazon.IdentityStore;
using Amazon.IdentityStore.Model;
using Amazon.SSOAdmin;
using Amazon.SSOAdmin.Model;
using static AwsAccessGraph.Constants;

namespace AwsAccessGraph.AwsPolicies
{
    public static class AwsPolicyLoader
    {
        public static int CachedHours { get; set; } = int.MaxValue;

        private static AmazonIdentityManagementServiceClient? iamClient = null;

        private static AmazonIdentityStoreClient? identityStoreClient = null;
        private static AmazonSSOAdminClient? identityCenterClient = null;

        public static async Task<(
            List<GroupDetail> groupList,
            List<ManagedPolicyDetail> policyList,
            List<RoleDetail> roleList,
            List<UserDetail> userList,
            List<SAMLProviderListEntry> awsSamlIdPs,
            List<PermissionSet> permissionSetList,
            Dictionary<string, PolicyArn[]> permissionSetManagedPolicies,
            Dictionary<string, PermissionSetInlinePolicy[]> permissionSetInlinePolicies,
            List<Amazon.IdentityStore.Model.User> identityStoreUsers,
            List<Amazon.IdentityStore.Model.Group> identityStoreGroups,
            Dictionary<string, GroupMembership[]> identityStoreGroupMemberships,
            List<AccountAssignment> permissionSetAssignments,
            string actualAwsAccountId
            )> LoadAwsPolicyAsync(
                Func<(
                    string? awsAccessKeyId,
                    string? awsSecretAccessKey,
                    string? awsSessionToken,
                    string? awsAccountIdArg,
                    ExitCodes? exitCode)> awsCredentialLoader,
                string awsAccountId,
                string outputDirectory,
                bool forceRefresh,
                bool noFiles,
                CancellationToken cancellationToken)
        {
            var actualAwsAccountId = new string(awsAccountId);

            var stsClientFactory = Globals.GetStsClientFactory(awsCredentialLoader);
            var iamClientFactory = new Lazy<AmazonIdentityManagementServiceClient>(() =>
            {
                Console.Error.Write("Getting IAM client... ");
                var (awsAccessKeyId, awsSecretAccessKey, awsSessionToken, awsAccountIdArg, exitCode) = awsCredentialLoader();
                if (exitCode != null)
                    Environment.Exit((int)exitCode);

                if ((string.IsNullOrWhiteSpace(awsAccessKeyId)
                   || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                   && string.IsNullOrWhiteSpace(awsSessionToken))
                {
                    Console.Error.WriteLine("Error creating IAM client: AWS credentials were not provided.");
                    Environment.Exit((int)ExitCodes.AwsCredentialsNotSpecified);
                }

                var iam = new AmazonIdentityManagementServiceClient(
                    awsAccessKeyId,
                    awsSecretAccessKey,
                    awsSessionToken);
                Console.Error.WriteLine("[\u2713]");

                // If we created the IAM client, go ahead and also create the STS client 
                // to double-check the account id passed in matches the credential.
                if (stsClientFactory == null)
                {
                    Console.Error.WriteLine($"No AWS credentials were not provided.  Aborting STS client creation.");
                    System.Environment.Exit((int)Constants.ExitCodes.AwsAccountIdMissing);
                }
                else if (!stsClientFactory.IsValueCreated)
                {
                    var stsClient = stsClientFactory.Value;
                    var identity = stsClient.GetCallerIdentityAsync(new Amazon.SecurityToken.Model.GetCallerIdentityRequest(), cancellationToken).Result;
                    actualAwsAccountId = identity.Account;

                    if (string.CompareOrdinal(actualAwsAccountId, awsAccountId) != 0)
                    {
                        Console.Error.WriteLine($"WARN: The specified Account ID {awsAccountId} does not match the AccountId {actualAwsAccountId} read from STS.  Assuming we are actually analyzing AWS Account {actualAwsAccountId}");
                    }
                }

                return iam;
            });

            var identityCenterClientFactory = new Lazy<AmazonSSOAdminClient>(() =>
            {
                Console.Error.Write("Getting SSO Admin (Identity Center) client... ");

                var (awsAccessKeyId, awsSecretAccessKey, awsSessionToken, awsAccountIdArg, exitCode) = awsCredentialLoader();
                if ((string.IsNullOrWhiteSpace(awsAccessKeyId)
                   || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                   && string.IsNullOrWhiteSpace(awsSessionToken))
                {
                    Console.Error.WriteLine("Error creating SSO Admin (Identity Center) client: AWS credentials were not provided.");
                    System.Environment.Exit((int)ExitCodes.AwsCredentialsNotSpecified);
                }

                var identityCenterClient = new AmazonSSOAdminClient(
                    awsAccessKeyId,
                    awsSecretAccessKey,
                    awsSessionToken);
                Console.Error.WriteLine("[\u2713]");

                return identityCenterClient;
            });

            var identityStoreClientFactory = new Lazy<AmazonIdentityStoreClient>(() =>
            {
                Console.Error.Write("Getting Identity Store client... ");
                var (awsAccessKeyId, awsSecretAccessKey, awsSessionToken, awsAccountIdArg, exitCode) = awsCredentialLoader();
                if ((string.IsNullOrWhiteSpace(awsAccessKeyId)
                   || string.IsNullOrWhiteSpace(awsSecretAccessKey))
                   && string.IsNullOrWhiteSpace(awsSessionToken))
                {
                    Console.Error.WriteLine("Error creating Identity Store client: AWS credentials were not provided.");
                    Environment.Exit((int)ExitCodes.AwsCredentialsNotSpecified);
                }

                var identityStoreClient = new AmazonIdentityStoreClient(
                    awsAccessKeyId,
                    awsSecretAccessKey,
                    awsSessionToken);
                Console.Error.WriteLine("[\u2713]");

                return identityStoreClient;
            });

            if (string.IsNullOrWhiteSpace(actualAwsAccountId))
            {
                if (stsClientFactory == null)
                {
                    Console.Error.WriteLine($"No AWS credentials were not provided.  Aborting STS client creation.");
                    System.Environment.Exit((int)Constants.ExitCodes.AwsAccountIdMissing);
                }

                var stsClient = stsClientFactory.Value;
                var identity = await stsClient.GetCallerIdentityAsync(new Amazon.SecurityToken.Model.GetCallerIdentityRequest(), cancellationToken);
                actualAwsAccountId = identity.Account;
            }
            Console.Error.WriteLine($"Analyzing AWS Account {actualAwsAccountId}");

            // ############################################
            // ### Account Authorization Details Report ###
            // ############################################
            List<GroupDetail>? groupList = null;
            List<ManagedPolicyDetail>? policyList = null;
            List<RoleDetail>? roleList = null;
            List<UserDetail>? userList = null;
            List<SAMLProviderListEntry>? samlIdpList = null;
            List<PermissionSet>? permissionSetList = null;
            Dictionary<string, PolicyArn[]>? permissionSetManagedPolicies = null;
            Dictionary<string, PermissionSetInlinePolicy[]>? permissionSetInlinePolicies = null;
            List<Amazon.IdentityStore.Model.User>? identityStoreUsers = null;
            List<Amazon.IdentityStore.Model.Group>? identityStoreGroups = null;
            Dictionary<string, GroupMembership[]>? identityStoreGroupMemberships = null;
            List<AccountAssignment>? permissionSetAssignments = null;

            {
                Console.Error.WriteLine("Enumerating Account Authorization Details... ");
                string groupListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-group-list.json");
                string policyListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-policy-list.json");
                string roleListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-role-list.json");
                string userListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-user-list.json");
                string samlIdpListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-saml-idp-list.json");
                string permissionSetListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-permission-set-list.json");
                string permissionSetManagedPolicyMapPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-permission-set-managed-policy-map.json");
                string permissionSetInlinePolicyMapPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-permission-set-inline-policy-map.json");
                string identityStoreUserListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-identity-store-user-list.json");
                string identityStoreGroupListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-identity-store-group-list.json");
                string identityStoreGroupMembershipMapPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-identity-store-group-members-map.json");
                string permissionSetAssignmentListPath() => Path.Combine(outputDirectory, $"aws-{actualAwsAccountId}-permission-set-assignments-list.json");

                async Task<T?> loadFromCache<T, V>(string path, string collectionName, bool forceRefresh, CancellationToken cancellationToken) where T : ICollection<V>
                {
                    if (!forceRefresh
                        && File.Exists(path)
                        && (DateTime.UtcNow - File.GetLastWriteTimeUtc(path)).TotalHours < CachedHours)
                    {
                        try
                        {
                            T? result;
                            using (var fs = new FileStream(path, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }))
                            {
                                result = await JsonSerializer.DeserializeAsync<T>(fs, cancellationToken: cancellationToken);
                            }
                            Console.Error.WriteLine($"[\u2713] {result!.Count} {collectionName} read from cache.");
                            return result;
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Error reading from AWS {collectionName} cache{Environment.NewLine}Message:{ex.Message}{Environment.NewLine}.  Will try to ready from API.");
                            return default(T?);
                        }
                    }
                    return default(T?);
                }

                groupList = await loadFromCache<List<GroupDetail>, GroupDetail>(groupListPath(), "groups", forceRefresh, cancellationToken);
                policyList = await loadFromCache<List<ManagedPolicyDetail>, ManagedPolicyDetail>(policyListPath(), "policies", forceRefresh, cancellationToken);
                roleList = await loadFromCache<List<RoleDetail>, RoleDetail>(roleListPath(), "roles", forceRefresh, cancellationToken);
                userList = await loadFromCache<List<UserDetail>, UserDetail>(userListPath(), "users", forceRefresh, cancellationToken);

                if (groupList == null
                    || policyList == null
                    || roleList == null
                    || userList == null)
                {
                    // None of this was read from cache, so read fresh if we can.
                    groupList = [];
                    policyList = [];
                    roleList = [];
                    userList = [];
                    var more = false;
                    string? marker = null;
                    iamClient ??= iamClientFactory.Value;

                    Console.Error.WriteLine($"Reading data from GetAccountAuthorizationDetailsAsync.  In large accounts, this could take a few minutes...");
                    int page = 1;
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

                        if (more)
                            Console.Error.WriteLine($"\tProcessed page {page}... ");
                        page++;

                    } while (more && !cancellationToken.IsCancellationRequested);
                    Console.Error.WriteLine($"[\u2713] {groupList.Count} groups, {policyList.Count} policies, {roleList.Count} roles, {userList.Count} users read from AWS API.");
                    if (!noFiles
                        && (groupList.Count != 0 || policyList.Count != 0 || roleList.Count != 0 || userList.Count != 0))
                    {
                        if (!Directory.Exists(outputDirectory))
                            Directory.CreateDirectory(outputDirectory);

                        await File.WriteAllTextAsync(groupListPath(), JsonSerializer.Serialize(groupList), cancellationToken);
                        await File.WriteAllTextAsync(policyListPath(), JsonSerializer.Serialize(policyList), cancellationToken);
                        await File.WriteAllTextAsync(roleListPath(), JsonSerializer.Serialize(roleList), cancellationToken);
                        await File.WriteAllTextAsync(userListPath(), JsonSerializer.Serialize(userList), cancellationToken);
                    }
                }

                // SAML providers, separate call.
                samlIdpList = await loadFromCache<List<SAMLProviderListEntry>, SAMLProviderListEntry>(samlIdpListPath(), "SAML providers", forceRefresh, cancellationToken);
                if (samlIdpList == null)
                {
                    // None of this was read from cache, so read fresh if we can.
                    samlIdpList = [];
                    iamClient ??= iamClientFactory.Value;
                    var response = await iamClient.ListSAMLProvidersAsync(new ListSAMLProvidersRequest(), cancellationToken);
                    samlIdpList.AddRange(response.SAMLProviderList);

                    Console.Error.WriteLine($"[\u2713] {samlIdpList.Count} SAML providers read from AWS API.");
                    if (!noFiles && samlIdpList.Count != 0)
                    {
                        if (!Directory.Exists(outputDirectory))
                            Directory.CreateDirectory(outputDirectory);
                        await File.WriteAllTextAsync(samlIdpListPath(), JsonSerializer.Serialize(samlIdpList), cancellationToken);
                    }
                }

                // Identity Center objects, separate set of calls.
                permissionSetList = await loadFromCache<List<PermissionSet>, PermissionSet>(permissionSetListPath(), "permission sets", forceRefresh, cancellationToken);
                permissionSetManagedPolicies = await loadFromCache<Dictionary<string, PolicyArn[]>, KeyValuePair<string, PolicyArn[]>>(permissionSetManagedPolicyMapPath(), "permission set managed policies", forceRefresh, cancellationToken);
                permissionSetInlinePolicies = await loadFromCache<Dictionary<string, PermissionSetInlinePolicy[]>, KeyValuePair<string, PermissionSetInlinePolicy[]>>(permissionSetInlinePolicyMapPath(), "permission set inline policies", forceRefresh, cancellationToken);
                identityStoreUsers = await loadFromCache<List<Amazon.IdentityStore.Model.User>, Amazon.IdentityStore.Model.User>(identityStoreUserListPath(), "identity store users", forceRefresh, cancellationToken);
                identityStoreGroups = await loadFromCache<List<Amazon.IdentityStore.Model.Group>, Amazon.IdentityStore.Model.Group>(identityStoreGroupListPath(), "identity store groups", forceRefresh, cancellationToken);
                identityStoreGroupMemberships = await loadFromCache<Dictionary<string, Amazon.IdentityStore.Model.GroupMembership[]>, KeyValuePair<string, Amazon.IdentityStore.Model.GroupMembership[]>>(identityStoreGroupMembershipMapPath(), "identity store group members", forceRefresh, cancellationToken);
                permissionSetAssignments = await loadFromCache<List<AccountAssignment>, AccountAssignment>(permissionSetAssignmentListPath(), "permission set assignments", forceRefresh, cancellationToken);

                if (permissionSetList == null
                    || permissionSetManagedPolicies == null
                    || permissionSetInlinePolicies == null
                    || identityStoreUsers == null
                    || identityStoreGroups == null
                    || identityStoreGroupMemberships == null
                    || permissionSetAssignments == null)
                {
                    permissionSetList = [];
                    permissionSetManagedPolicies = [];
                    permissionSetInlinePolicies = [];
                    identityStoreUsers = [];
                    identityStoreGroups = [];
                    identityStoreGroupMemberships = [];
                    permissionSetAssignments = [];
                    identityCenterClient ??= identityCenterClientFactory.Value;
                    identityStoreClient ??= identityStoreClientFactory.Value;

                    var icInstancesResponse = await identityCenterClient.ListInstancesAsync(new ListInstancesRequest(), cancellationToken);
                    if (icInstancesResponse.Instances.Count == 0)
                    {
                        // There is no Identity Center.
                    }
                    else
                    {
                        var icErrorAndNoWriteCache = false;
                        foreach (var ici in icInstancesResponse.Instances)
                        {
                            Console.Error.WriteLine($"Identity Center {ici.InstanceArn} located in {actualAwsAccountId} (owner={ici.OwnerAccountId}).  This will take a moment..");
                            try
                            {
                                // Users
                                var more = false;
                                string? nextToken = null;
                                do
                                {
                                    var idsUserResponse = await identityStoreClient.ListUsersAsync(new Amazon.IdentityStore.Model.ListUsersRequest
                                    {
                                        IdentityStoreId = ici.IdentityStoreId,
                                        NextToken = nextToken
                                    }, cancellationToken);

                                    more = idsUserResponse.NextToken != null;
                                    nextToken = idsUserResponse.NextToken;
                                    identityStoreUsers.AddRange(idsUserResponse.Users);
                                } while (more && !cancellationToken.IsCancellationRequested);
                                Console.Error.WriteLine($"\t[\u2713] {identityStoreUsers.Count} users retrieved for identity store {ici.IdentityStoreId}.");

                                // Groups
                                more = false;
                                nextToken = null;
                                do
                                {
                                    var idsGroupResponse = await identityStoreClient.ListGroupsAsync(new Amazon.IdentityStore.Model.ListGroupsRequest
                                    {
                                        IdentityStoreId = ici.IdentityStoreId,
                                        NextToken = nextToken
                                    }, cancellationToken);

                                    more = idsGroupResponse.NextToken != null;
                                    nextToken = idsGroupResponse.NextToken;
                                    identityStoreGroups.AddRange(idsGroupResponse.Groups);
                                } while (more && !cancellationToken.IsCancellationRequested);
                                Console.Error.WriteLine($"\t[\u2713] {identityStoreGroups.Count} groups retrieved for identity store {ici.IdentityStoreId}.");

                                // Group Memberships
                                foreach (var g in identityStoreGroups)
                                {
                                    more = false;
                                    nextToken = null;

                                    do
                                    {
                                        var groupMembershipsResponse = await identityStoreClient.ListGroupMembershipsAsync(new ListGroupMembershipsRequest
                                        {
                                            IdentityStoreId = ici.IdentityStoreId,
                                            GroupId = g.GroupId,
                                            NextToken = nextToken
                                        }, cancellationToken);

                                        more = groupMembershipsResponse.NextToken != null;
                                        nextToken = groupMembershipsResponse.NextToken;

                                        var members = groupMembershipsResponse.GroupMemberships;
                                        if (identityStoreGroupMemberships.TryGetValue(g.GroupId, out GroupMembership[]? membersExisting))
                                        {
                                            var z = new GroupMembership[membersExisting.Length + members.Count];
                                            membersExisting.CopyTo(z, 0);
                                            members.CopyTo(z, membersExisting.Length);
                                            identityStoreGroupMemberships[g.GroupId] = z;
                                        }
                                        else
                                            identityStoreGroupMemberships.Add(g.GroupId, [.. members]);

                                    } while (more && !cancellationToken.IsCancellationRequested);

                                }

                                // Permission Sets
                                more = false;
                                nextToken = null;
                                var permissionSetArns = new List<string>();
                                do
                                {
                                    var lpResponse = await identityCenterClient.ListPermissionSetsAsync(new ListPermissionSetsRequest
                                    {
                                        InstanceArn = ici.InstanceArn,
                                        NextToken = nextToken
                                    }, cancellationToken);

                                    more = lpResponse.NextToken != null;
                                    nextToken = lpResponse.NextToken;
                                    permissionSetArns.AddRange(lpResponse.PermissionSets);
                                } while (more && !cancellationToken.IsCancellationRequested);
                                Console.Error.WriteLine($"\t[\u2713] {permissionSetArns.Count} permission sets read from AWS API, getting details of each now...");

                                foreach (var psArn in permissionSetArns)
                                {
                                    var pResponse = await identityCenterClient.DescribePermissionSetAsync(new DescribePermissionSetRequest
                                    {
                                        PermissionSetArn = psArn,
                                        InstanceArn = ici.InstanceArn
                                    }, cancellationToken);
                                    permissionSetList!.Add(pResponse.PermissionSet);

                                    // Managed policies attached to a permission set
                                    more = false;
                                    nextToken = null;
                                    do
                                    {
                                        var managedPoliciesResponse = await identityCenterClient.ListManagedPoliciesInPermissionSetAsync(new ListManagedPoliciesInPermissionSetRequest
                                        {
                                            InstanceArn = ici.InstanceArn,
                                            PermissionSetArn = psArn,
                                            NextToken = nextToken
                                        }, cancellationToken);

                                        more = managedPoliciesResponse.NextToken != null;
                                        nextToken = managedPoliciesResponse.NextToken;
                                        var managedPolicies = managedPoliciesResponse.AttachedManagedPolicies.Select(m => m.Arn).ToList();
                                        if (permissionSetManagedPolicies!.TryGetValue(psArn, out string[]? managedPoliciesExisting))
                                        {
                                            var z = new string[managedPoliciesExisting.Length + managedPolicies.Count];
                                            managedPoliciesExisting.CopyTo(z, 0);
                                            managedPolicies.CopyTo(z, managedPoliciesExisting.Length);
                                            permissionSetManagedPolicies[psArn] = z;
                                        }
                                        else
                                            permissionSetManagedPolicies.Add(psArn, [.. managedPolicies]);

                                    } while (more && !cancellationToken.IsCancellationRequested);

                                    // Inline policies attached to a permission set
                                    more = false;
                                    nextToken = null;
                                    List<PermissionSetInlinePolicy> inlinePolicies = [];
                                    do
                                    {
                                        var customerPoliciesResponse = await identityCenterClient.ListCustomerManagedPolicyReferencesInPermissionSetAsync(new ListCustomerManagedPolicyReferencesInPermissionSetRequest
                                        {
                                            InstanceArn = ici.InstanceArn,
                                            PermissionSetArn = psArn,
                                            NextToken = nextToken
                                        }, cancellationToken);

                                        more = customerPoliciesResponse.NextToken != null;
                                        nextToken = customerPoliciesResponse.NextToken;
                                        foreach (var ip in customerPoliciesResponse.CustomerManagedPolicyReferences)
                                        {
                                            var policyDocument = await identityCenterClient.GetInlinePolicyForPermissionSetAsync(new GetInlinePolicyForPermissionSetRequest
                                            {
                                                InstanceArn = ici.InstanceArn,
                                                PermissionSetArn = psArn
                                            }, cancellationToken);

                                            inlinePolicies.Add(new PermissionSetInlinePolicy
                                            {
                                                Name = ip.Name,
                                                Path = ip.Path,
                                                PolicyDocument = policyDocument.InlinePolicy
                                            });
                                        }

                                        if (permissionSetInlinePolicies!.TryGetValue(psArn, out PermissionSetInlinePolicy[]? inlinePoliciesExisting))
                                        {
                                            var z = new PermissionSetInlinePolicy[inlinePoliciesExisting.Length + inlinePolicies.Count];
                                            inlinePoliciesExisting.CopyTo(z, 0);
                                            inlinePolicies.CopyTo(z, inlinePoliciesExisting.Length);
                                            permissionSetInlinePolicies[psArn] = z;
                                        }
                                        else
                                            permissionSetInlinePolicies.Add(psArn, [.. inlinePolicies]);
                                    } while (more && !cancellationToken.IsCancellationRequested);

                                    // Now read permission set assignments.
                                    more = false;
                                    nextToken = null;
                                    do
                                    {
                                        var icAccountAssignmentsResponse = await identityCenterClient.ListAccountAssignmentsAsync(new ListAccountAssignmentsRequest
                                        {
                                            AccountId = awsAccountId,
                                            InstanceArn = ici.InstanceArn,
                                            PermissionSetArn = psArn,
                                            NextToken = nextToken
                                        }, cancellationToken);

                                        more = icAccountAssignmentsResponse.NextToken != null;
                                        nextToken = icAccountAssignmentsResponse.NextToken;
                                        permissionSetAssignments!.AddRange(icAccountAssignmentsResponse.AccountAssignments);
                                    } while (more && !cancellationToken.IsCancellationRequested);
                                }
                            }
                            catch (Amazon.SSOAdmin.Model.AccessDeniedException ade)
                            {
                                Console.Error.WriteLine($"[X] ERROR reading permission sets from AWS API for Identity Center {ici.InstanceArn}: {ade.Message}");
                                icErrorAndNoWriteCache = true;
                            }

                            if (!icErrorAndNoWriteCache)
                                Console.Error.WriteLine($"\t[\u2713] {(permissionSetList == null ? 0 : permissionSetList.Count)} permission sets, {(permissionSetManagedPolicies == null ? 0 : permissionSetManagedPolicies.SelectMany(p => p.Value).Count())} managed policy references, {(permissionSetInlinePolicies == null ? 0 : permissionSetInlinePolicies.SelectMany(p => p.Value).Count())} inline policy references, and {(permissionSetAssignments == null ? 0 : permissionSetAssignments.Count())} assignments read from AWS API.");
                        }

                        if (!noFiles && !icErrorAndNoWriteCache)
                        {
                            if (!Directory.Exists(outputDirectory))
                                Directory.CreateDirectory(outputDirectory);

                            await File.WriteAllTextAsync(permissionSetListPath(), JsonSerializer.Serialize(permissionSetList ?? []), cancellationToken);
                            await File.WriteAllTextAsync(permissionSetManagedPolicyMapPath(), JsonSerializer.Serialize(permissionSetManagedPolicies ?? []), cancellationToken);
                            await File.WriteAllTextAsync(permissionSetInlinePolicyMapPath(), JsonSerializer.Serialize(permissionSetInlinePolicies ?? []), cancellationToken);
                            await File.WriteAllTextAsync(identityStoreUserListPath(), JsonSerializer.Serialize(identityStoreUsers ?? []), cancellationToken);
                            await File.WriteAllTextAsync(identityStoreGroupListPath(), JsonSerializer.Serialize(identityStoreGroups ?? []), cancellationToken);
                            await File.WriteAllTextAsync(identityStoreGroupMembershipMapPath(), JsonSerializer.Serialize(identityStoreGroupMemberships ?? []), cancellationToken);
                            await File.WriteAllTextAsync(permissionSetAssignmentListPath(), JsonSerializer.Serialize(permissionSetAssignments ?? []), cancellationToken);
                        }
                    }
                }

                // However, we will prune our memory copy to only care about policies with attachments.
                //policyList = policyList.Where(p => p.AttachmentCount > 0).ToList();
            }

            return (groupList!, policyList!, roleList!, userList!, samlIdpList!, permissionSetList!, permissionSetManagedPolicies!, permissionSetInlinePolicies!, identityStoreUsers!, identityStoreGroups!, identityStoreGroupMemberships!, permissionSetAssignments!, actualAwsAccountId!);
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

            Console.Error.WriteLine("Enumerating Service Last Action action details... ");

            // Get this for each role.
            var roleJobIds = new Queue<(string RoleId, string JobId)>(roleList.Count);
            foreach (var role in roleList)
            {
                var roleActionDetailsPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-role-{role.RoleId}-service-last-action-report.json");
                if (!forceRefresh
                   && File.Exists(roleActionDetailsPath)
                   && (DateTime.UtcNow - File.GetLastWriteTimeUtc(roleActionDetailsPath)).TotalHours < CachedHours)
                {
                    iamClient ??= iamClientFactory.Value;
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

            Dictionary<string, EntityDetails[]> roleEntityDetailList = [];

            while (roleJobIds.Count > 0)
            {
                var nextRole = roleJobIds.Peek();
                var roleActionDetailsPath = Path.Combine(outputDirectory, $"aws-{awsAccountId}-role-{nextRole.RoleId}-service-last-action-report.json");
                var more = false;
                string? marker = null;
                iamClient ??= iamClientFactory.Value;

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

                roleEntityDetailList.Add(nextRole.RoleId, [.. entitiesDetailsList]);
                roleJobIds.Dequeue();
            }

            return roleEntityDetailList;
        }
    }
}