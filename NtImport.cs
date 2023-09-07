namespace UndeadInterop
{
    [AttributeUsage(AttributeTargets.Delegate)]
    public sealed class NtImport : Attribute
    {
        public string? Entrypoint { get; }

        public NtImport(string? entrypoint = null)
        {
            Entrypoint = entrypoint;
        }
    }
}
