﻿using System;
using System.Data;
using System.Data.Common;
using System.Data.SQLite;

namespace SQLiteMembership
{
    public class SQLiteMembershipUtils
    {
        private static readonly object SyncObject = new object();

        public static void CreateDatabaseIfRequired(string connectionString, string applicationName)
        {
            lock (SyncObject)
            {
                var builder = new SQLiteConnectionStringBuilder
                {
                    ConnectionString = connectionString
                };
                var sdfPath = ReplaceDataDirectory(builder.DataSource);

                if (string.IsNullOrWhiteSpace(sdfPath))
                    return;

                ValidateDatabase(connectionString, applicationName);
            }
        }

        public static string GetApplicationId(string connectionString, string applicationName)
        {
            using (var con = GetConnection(connectionString))
            {
                con.Open();

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "SELECT [ApplictionId] FROM [aspnet_Applications] WHERE [ApplicationName]=@ApplicationName";
                    cmd.Parameters.Add(GetParameter("@ApplicationName", applicationName));

                    var applicationId = cmd.ExecuteScalar();

                    if (applicationId == null)
                        throw new System.Configuration.Provider.ProviderException("Unable to find application id for provided application name: " + applicationName);

                    return applicationId as string;

                }
            }
        }

        private static string ReplaceDataDirectory(string inputString)
        {
            var str = inputString.Trim();

            if (string.IsNullOrEmpty(inputString) || !inputString.StartsWith("|DataDirectory|", StringComparison.InvariantCultureIgnoreCase))
                return str;

            var data = AppDomain.CurrentDomain.GetData("DataDirectory") as string;

            if (string.IsNullOrEmpty(data))
                data = AppDomain.CurrentDomain.BaseDirectory;

            if (string.IsNullOrEmpty(data))
                data = string.Empty;

            var length = "|DataDirectory|".Length;

            if ((inputString.Length > "|DataDirectory|".Length) && ('\\' == inputString["|DataDirectory|".Length]))
                length++;

            return System.IO.Path.Combine(data, inputString.Substring(length));
        }

        private static void ValidateDatabase(string connectionString, string applicationName)
        {
            using (var con = GetConnection(connectionString))
            {
                con.Open();

                using (var cmd = con.CreateCommand())
                {
                    CreateApplications(cmd, applicationName);
                    CreateRoles(cmd);
                    CreateUsers(cmd);
                    CreateUsersInRoles(cmd);
                    CreateProfile(cmd);
                }
            }
        }

        private static DbConnection GetConnection(string connectionString)
        {
            return new SQLiteConnection(connectionString);
        }

        private static DbParameter GetParameter(string parameterName, object value)
        {
            return new SQLiteParameter(parameterName, value);
        }

        private static void CreateApplications(IDbCommand cmd, string applicationName)
        {
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS [aspnet_Applications] (
	                                    [ApplicationId] TEXT PRIMARY KEY NOT NULL,
	                                    [ApplicationName] NVARCHAR(256) NOT NULL,
	                                    [LoweredApplicationName] NVARCHAR(256) NOT NULL,
	                                    [Description] NVARCHAR(256) NULL
                                    );";
            cmd.ExecuteNonQuery();

            cmd.CommandText =
                @"CREATE INDEX IF NOT EXISTS [aspnet_Applications_Index] ON [aspnet_Applications] ([LoweredApplicationName] ASC);";
            cmd.ExecuteNonQuery();

            cmd.CommandText =
                @"CREATE UNIQUE INDEX IF NOT EXISTS [UQ__A__3091033107020F21] ON [aspnet_Applications] ([ApplicationName] ASC);";
            cmd.ExecuteNonQuery();

            cmd.CommandText = @"INSERT OR IGNORE INTO [aspnet_Applications] (
                                            [ApplicationName], 
                                            [LoweredApplicationName], 
                                            [ApplicationId]
                                        ) VALUES (
                                            @ApplicationName,
                                            @LoweredApplicationName,
                                            @ApplicationId
                                        );";
            cmd.Parameters.Add(GetParameter("@ApplicationName", applicationName));
            cmd.Parameters.Add(GetParameter("@LoweredApplicationName", applicationName.ToLowerInvariant()));
            cmd.Parameters.Add(GetParameter("@ApplicationId", Guid.NewGuid().ToString()));
            cmd.ExecuteNonQuery();
        }

        private static void CreateRoles(IDbCommand cmd)
        {
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS [aspnet_Roles] (
	                                [ApplicationId] TEXT NOT NULL,
	                                [RoleId] TEXT PRIMARY KEY NOT NULL,
	                                [RoleName] NVARCHAR(256) NOT NULL,
	                                [LoweredRoleName] NVARCHAR(256) NOT NULL,
	                                [Description] NVARCHAR(256) NULL,
	                                FOREIGN KEY ([ApplicationId]) REFERENCES [aspnet_Applications]([ApplicationId]) ON DELETE NO ACTION ON UPDATE NO ACTION
                                );";
            cmd.ExecuteNonQuery();
        }

        private static void CreateUsers(IDbCommand cmd)
        {
            cmd.CommandText =
                    @"CREATE TABLE IF NOT EXISTS [aspnet_Users] (
                        [ApplicationId] TEXT NOT NULL,
	                    [UserId] TEXT PRIMARY KEY NOT NULL,
	                    [UserName] NVARCHAR(256) NOT NULL,
	                    [LoweredUserName] NVARCHAR(256) NOT NULL,
	                    [MobileAlias] NVARCHAR(16) NULL,
	                    [IsAnonymous] INTEGER NOT NULL CHECK ([IsAnonymous] IN (0, 1)),
	                    [LastActivityDate] DATETIME NOT NULL,
	                    FOREIGN KEY ([ApplicationId]) REFERENCES [aspnet_Applications]([ApplicationId]) ON DELETE NO ACTION ON UPDATE NO ACTION
                    );";
            cmd.ExecuteNonQuery();

            cmd.CommandText =
                @"CREATE UNIQUE INDEX IF NOT EXISTS [aspnet_Users_Index] ON [aspnet_Users] ([ApplicationId] ASC,[LoweredUserName] ASC);";
            cmd.ExecuteNonQuery();

            cmd.CommandText =
                @"CREATE INDEX IF NOT EXISTS [aspnet_Users_Index2] ON [aspnet_Users] ([ApplicationId] ASC,[LastActivityDate] ASC);";
            cmd.ExecuteNonQuery();

            cmd.CommandText =
                @"CREATE TABLE IF NOT EXISTS [aspnet_Membership] (
                    [ApplicationId] TEXT NOT NULL,
	                [UserId] TEXT PRIMARY KEY NOT NULL,
	                [Password] NVARCHAR(128) NOT NULL,
	                [PasswordFormat] INTEGER NOT NULL,
	                [PasswordSalt] NVARCHAR(128) NOT NULL,
	                [MobilePIN] NVARCHAR(16) NULL,
	                [Email] NVARCHAR(256) NULL,
	                [LoweredEmail] NVARCHAR(256) NULL,
	                [PasswordQuestion] NVARCHAR(256) NULL,
	                [PasswordAnswer] NVARCHAR(256) NULL,
	                [IsApproved] INTEGER NOT NULL CHECK ([IsApproved] IN (0, 1)),
	                [IsLockedOut] INTEGER NOT NULL CHECK ([IsLockedOut] IN (0, 1)),
	                [CreateDate] DATETIME DEFAULT (datetime('now','localtime')) NOT NULL,
	                [LastLoginDate] DATETIME NOT NULL,
	                [LastPasswordChangedDate] DATETIME NOT NULL,
	                [LastLockoutDate] DATETIME NOT NULL,
	                [FailedPasswordAttemptCount] INTEGER NOT NULL,
	                [FailedPasswordAttemptWindowStart] DATETIME NOT NULL,
	                [FailedPasswordAnswerAttemptCount] INTEGER NOT NULL,
	                [FailedPasswordAnswerAttemptWindowStart] DATETIME NOT NULL,
	                [Comment] NTEXT NULL,
	                FOREIGN KEY ([ApplicationId]) REFERENCES [aspnet_Applications]([ApplicationId]) ON DELETE NO ACTION ON UPDATE NO ACTION,
	                FOREIGN KEY ([UserId]) REFERENCES [aspnet_Users]([UserId]) ON DELETE NO ACTION ON UPDATE NO ACTION
                );";
            cmd.ExecuteNonQuery();

            cmd.CommandText =
                @"CREATE INDEX IF NOT EXISTS [aspnet_Membership_index] ON [aspnet_Membership] ([ApplicationId] ASC,[LoweredEmail] ASC);";
            cmd.ExecuteNonQuery();
        }

        private static void CreateUsersInRoles(IDbCommand cmd)
        {
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS [aspnet_UsersInRoles] (
	                                [UserId] TEXT NOT NULL,
	                                [RoleId] TEXT NOT NULL,
	                                PRIMARY KEY ([UserId], [RoleId]),
	                                FOREIGN KEY ([UserId]) REFERENCES [aspnet_Users]([UserId]) ON DELETE NO ACTION ON UPDATE NO ACTION,
	                                FOREIGN KEY ([RoleId]) REFERENCES [aspnet_Roles]([RoleId]) ON DELETE NO ACTION ON UPDATE NO ACTION
                                );";
            cmd.ExecuteNonQuery();

            cmd.CommandText = @"CREATE INDEX IF NOT EXISTS [aspnet_UsersInRoles_index] ON [aspnet_UsersInRoles] ([RoleId] ASC);";
            cmd.ExecuteNonQuery();
        }

        private static void CreateProfile(IDbCommand cmd)
        {
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS [user_profiles] (
	                                [UserId] TEXT PRIMARY KEY NOT NULL,
	                                [property_names] NTEXT NOT NULL,
	                                [property_values_string] NTEXT NOT NULL,
	                                [property_values_binary] BLOB NOT NULL,
	                                [last_updated_date] DATETIME NOT NULL,
	                                FOREIGN KEY ([UserId]) REFERENCES [aspnet_Users]([UserId]) ON DELETE NO ACTION ON UPDATE NO ACTION
                                );";
            cmd.ExecuteNonQuery();
        }
    }
}