namespace SQLiteMembership
{
    static class StringExtensions
    {
        public static string DefaultIfEmpty(this string source, string defaultValue)
        {
            return string.IsNullOrWhiteSpace(source) ? defaultValue : source;
        }
    }
}
