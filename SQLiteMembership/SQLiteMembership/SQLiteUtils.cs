using System.Data.SQLite;

namespace SQLiteMembership
{
    static class SQLiteUtils
    {
        public static SQLiteConnection GetConnection(string connectionString)
        {
            return new SQLiteConnection(connectionString);
        }
    }
}
