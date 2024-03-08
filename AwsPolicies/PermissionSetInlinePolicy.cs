namespace AwsAccessGraph.AwsPolicies
{
    public readonly record struct PermissionSetInlinePolicy
    {
        public string Name { get; init; }
        public string Path { get; init; }
        public string PolicyDocument { get; init; }
    }
}