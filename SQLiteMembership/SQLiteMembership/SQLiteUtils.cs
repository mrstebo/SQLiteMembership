using System.Data.SQLite;

namespace SQLiteMembership
{
    static class SQLiteUtils
    {
        public static SQLiteConnection GetConnection(string connectionString)
        {
            return new SQLiteConnection(connectionString);
        }

        public static SQLiteParameter CreateParameter(string parameterName, object value)
        {
            return new SQLiteParameter(parameterName, value);
        }
    }
}
