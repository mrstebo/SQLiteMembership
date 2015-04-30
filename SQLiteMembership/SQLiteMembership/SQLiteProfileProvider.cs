using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Hosting;
using System.Web.Profile;

namespace SQLiteMembership
{
    public sealed class SQLiteProfileProvider : ProfileProvider
    {
        private string _connectionString;
        private string _applicationId;

        public bool WriteExceptionsToEventLog { get; set; }
        public override string ApplicationName { get; set; }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            if (name.Length == 0)
                name = "SQLiteProfileProvider";

            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "SQLite Profile Provider");
            }

            base.Initialize(name, config);

            var connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];

            if (connectionStringSettings == null || string.IsNullOrWhiteSpace(connectionStringSettings.ConnectionString))
                throw new ProviderException("Connection string cannot be blank.");

            _connectionString = connectionStringSettings.ConnectionString;

            ApplicationName = config["applicationName"].DefaultIfEmpty(HostingEnvironment.ApplicationVirtualPath);

            SQLiteMembershipUtils.CreateDatabaseIfRequired(_connectionString, ApplicationName);

            _applicationId = SQLiteMembershipUtils.GetApplicationId(_connectionString, ApplicationName);

            config.Remove("connectionStringName");
            config.Remove("applicationName");

            if (config.Count > 0)
            {
                var attribUnrecognized = config.GetKey(0);

                if (!string.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException("Unrecognized attribute: " + attribUnrecognized);
            }
        }

        public override SettingsPropertyValueCollection GetPropertyValues(SettingsContext context,
            SettingsPropertyCollection collection)
        {
            var results = new SettingsPropertyValueCollection();

            if (collection.Count < 1)
                return results;

            var username = (string) context["UserName"];

            foreach (SettingsProperty prop in collection)
            {
                if (prop.SerializeAs == SettingsSerializeAs.ProviderSpecific)
                {
                    if (prop.PropertyType.IsPrimitive || prop.PropertyType == typeof (string))
                        prop.SerializeAs = SettingsSerializeAs.String;
                    else
                        prop.SerializeAs = SettingsSerializeAs.Xml;
                }

                results.Add(new SettingsPropertyValue(prop));
            }

            if (!string.IsNullOrWhiteSpace(username))
                GetPropertyValuesFromDatabase(username, results);

            return results;
        }

        public override void SetPropertyValues(SettingsContext context, SettingsPropertyValueCollection collection)
        {
            var username = (string) context["UserName"];
            var isAuthenticated = (bool) context["IsAuthenticated"];

            if (string.IsNullOrEmpty(username) || collection.Count < 1)
                return;

            var names = string.Empty;
            var values = string.Empty;
            byte[] buffer = null;

            PrepareDataForSaving(ref names, ref values, ref buffer, true, collection, isAuthenticated);
            if (names.Length == 0)
                return;

            using (var con = SQLiteUtils.GetConnection(_connectionString))
            {
                con.Open();

                int userCount;

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "SELECT Count(UserId) " +
                                      "FROM aspnet_Users " +
                                      "WHERE ApplicationId = @ApplicationId AND LoweredUserName = LOWER(@UserName)";
                    cmd.Parameters.AddRange(new[]
                    {
                        cmd.CreateParameter("@ApplicationId", _applicationId),
                        cmd.CreateParameter("@UserName", username)
                    });

                    userCount = (int) cmd.ExecuteScalar();
                }

                string userId;

                if (userCount.Equals(0))
                {
                    userId = Guid.NewGuid().ToString();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "INSERT INTO [aspnet_Users] ( " +
                                          "[ApplicationId], " +
                                          "[UserId], " +
                                          "[UserName], " +
                                          "[LoweredUserName], " +
                                          "[IsAnonymous], " +
                                          "[LastActivityDate] " +
                                          ") VALUES (" +
                                          "@ApplicationId, " +
                                          "@UserId, " +
                                          "@UserName, " +
                                          "@LoweredUserName, " +
                                          "@IsAnonymous, " +
                                          "@LastActivityDate)";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@UserId", userId),
                            cmd.CreateParameter("@UserName", username),
                            cmd.CreateParameter("@LoweredUserName", username.ToLowerInvariant()),
                            cmd.CreateParameter("@IsAnonymous", !isAuthenticated),
                            cmd.CreateParameter("@LastActivityDate", DateTime.UtcNow)
                        });

                        cmd.ExecuteNonQuery();
                    }
                }
                else if (userCount > 1)
                {
                    throw new Exception(
                        string.Format("Duplicate user records found for username '{0}' and application '{1}'",
                            username,
                            ApplicationName));
                }

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "SELECT UserId " +
                                      "FROM [aspnet_Users] " +
                                      "WHERE ApplicationId = @ApplicationId AND LoweredUserName = LOWER(@UserName)";

                    userId = cmd.ExecuteScalar() as string;
                }

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "UPDATE [aspnet_Users] " +
                                      "SET LastActivityDate=@CurrentTimeUtc " +
                                      "WHERE UserId = @UserId";
                    cmd.Parameters.AddRange(new[]
                    {
                        cmd.CreateParameter("@CurrentTimeUtc", DateTime.UtcNow),
                        cmd.CreateParameter("@UserId", userId)
                    });
                }

                int profileCount;

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "SELECT COUNT(UserId) " +
                                      "FROM aspnet_Profile " +
                                      "WHERE UserId = @UserId";
                    cmd.Parameters.Add(cmd.CreateParameter("@UserId", userId));

                    profileCount = (int) cmd.ExecuteScalar();
                }

                using (var cmd = con.CreateCommand())
                {
                    if (profileCount == 0)
                    {

                        cmd.CommandText = "INSERT INTO [aspnet_Profile] (" +
                                          "UserId, " +
                                          "PropertyNames, " +
                                          "PropertyValuesString, " +
                                          "PropertyValuesBinary, " +
                                          "LastUpdatedDate" +
                                          ") VALUES ( " +
                                          "@UserId, " +
                                          "@PropertyNames, " +
                                          "@PropertyValuesString, " +
                                          "@PropertyValuesBinary, " +
                                          "@CurrentTimeUtc)";
                    }
                    else
                    {
                        cmd.CommandText = "UPDATE [aspnet_Profile] " +
                                          "SET " +
                                          "PropertyNames = @PropertyNames, " +
                                          "PropertyValuesString = @PropertyValuesString, " +
                                          "PropertyValuesBinary = @PropertyValuesBinary, " +
                                          "LastUpdatedDate = @CurrentTimeUtc " +
                                          "WHERE UserId = @UserId";
                    }
                    cmd.Parameters.AddRange(new[]
                    {
                        cmd.CreateParameter("@PropertyNames", names),
                        cmd.CreateParameter("@PropertyValuesString", values),
                        cmd.CreateParameter("@PropertyValuesBinary", buffer),
                        cmd.CreateParameter("@CurrentTimeUtc", DateTime.UtcNow),
                        cmd.CreateParameter("@UserId", userId)
                    });

                    cmd.ExecuteNonQuery();
                }
            }
        }

        public override int DeleteProfiles(ProfileInfoCollection profiles)
        {
            var rowsAffected = 0;

            try
            {
                if (profiles.Count < 1)
                    throw new ArgumentException("The collection parameter 'profiles' should not be empty.", "profiles");

                var usernames = profiles
                    .Cast<ProfileInfo>()
                    .Select(x => x.UserName)
                    .ToArray();

                rowsAffected = DeleteProfiles(usernames);
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "DeleteProfiles(ProfileInfoCollection)");
            }

            return rowsAffected;
        }

        public override int DeleteProfiles(string[] usernames)
        {
            var rowsAffected = 0;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var transaction = con.BeginTransaction())
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_Profile] WHERE @UserId = UserId";

                            foreach (var username in usernames)
                            {
                                cmd.Parameters.Clear();

                                cmd.Parameters.Add(cmd.CreateParameter("@UserId", GetUserId(username)));

                                rowsAffected += cmd.ExecuteNonQuery();
                            }
                        }

                        transaction.Commit();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "DeleteProfiles(String[])");
            }

            return rowsAffected;
        }

        public override int DeleteInactiveProfiles(ProfileAuthenticationOption authenticationOption,
            DateTime userInactiveSinceDate)
        {
            var rowsAffected = 0;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    var userIds = new List<string>();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT UserId " +
                                          "FROM [aspnet_Users] " +
                                          "WHERE ApplicationId = @ApplicationId AND LastActivityDate <= @InactiveSinceDate AND (@ProfileAuthOptions = 2 OR (@ProfileAuthOptions = 0 AND IsAnonymous = 1) OR (@ProfileAuthOptions = 1 AND IsAnonymous = 0))";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@ProfileAuthOptions", (int) authenticationOption),
                            cmd.CreateParameter("@InactiveSinceDate", userInactiveSinceDate.ToUniversalTime())
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                userIds.Add(reader.GetString(0));
                            }
                        }
                    }

                    using (var transaction = con.BeginTransaction())
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_Profile] WHERE UserId = @UserId";

                            foreach (var userId in userIds)
                            {
                                cmd.Parameters.Clear();

                                cmd.Parameters.Add(cmd.CreateParameter("@UserId", userId));

                                rowsAffected += cmd.ExecuteNonQuery();
                            }
                        }

                        transaction.Commit();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "DeleteInactiveProfiles");
            }

            return rowsAffected;
        }

        public override int GetNumberOfInactiveProfiles(ProfileAuthenticationOption authenticationOption,
            DateTime userInactiveSinceDate)
        {
            var numberOfInactiveProfiles = 0;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    var userIds = new List<string>();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT UserId " +
                                          "FROM [aspnet_Users] " +
                                          "WHERE ApplicationId = @ApplicationId AND LastActivityDate <= @InactiveSinceDate AND (@ProfileAuthOptions = 2 OR (@ProfileAuthOptions = 0 AND IsAnonymous = 1) OR (@ProfileAuthOptions = 1 AND IsAnonymous = 0))";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@ProfileAuthOptions", (int) authenticationOption),
                            cmd.CreateParameter("@InactiveSinceDate", userInactiveSinceDate.ToUniversalTime())
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                userIds.Add(reader.GetString(0));
                            }
                        }
                    }

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = string.Format("SELECT COUNT(UserId) " +
                                                        "FROM [aspnet_Profile] " +
                                                        "WHERE UserId IN ('{0}')", string.Join("','", userIds));

                        numberOfInactiveProfiles = (int) cmd.ExecuteScalar();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "GetNumberOfInactiveProfiles");
            }

            return numberOfInactiveProfiles;
        }

        public override ProfileInfoCollection GetAllProfiles(ProfileAuthenticationOption authenticationOption,
            int pageIndex, int pageSize,
            out int totalRecords)
        {
            var results = new ProfileInfoCollection();

            totalRecords = 0;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText =
                            "SELECT aspnet_Users.UserName, aspnet_Users.IsAnonymous, aspnet_Users.LastActivityDate, aspnet_Profile.LastUpdatedDate, DATALENGTH(aspnet_Profile.PropertyNames) + DATALENGTH(aspnet_Profile.PropertyValuesString) + DATALENGTH(aspnet_Profile.PropertyValuesBinary) " +
                            "FROM aspnet_Users, aspnet_Profile " +
                            "WHERE aspnet_Users.UserId = aspnet_Profile.UserId AND ApplicationId = @ApplicationId AND (@ProfileAuthOptions = 2 OR (@ProfileAuthOptions = 0 AND IsAnonymous = 1) OR (@ProfileAuthOptions = 1 AND IsAnonymous = 0)) " +
                            "ORDER BY aspnet_Users.UserName Asc " +
                            "LIMIT @PageSize OFFSET @PageStart";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@ProfileAuthOptions", (int) authenticationOption),
                            cmd.CreateParameter("@PageSize", pageSize),
                            cmd.CreateParameter("@PageStart", pageIndex*pageSize)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess))
                        {
                            while (reader.Read())
                            {
                                var username = reader.GetString(0);
                                var isAnonymous = reader.GetBoolean(1);
                                var lastActivityDate = DateTime.SpecifyKind(reader.GetDateTime(2), DateTimeKind.Utc);
                                var lastUpdatedDate = DateTime.SpecifyKind(reader.GetDateTime(3), DateTimeKind.Utc);
                                var size = reader.GetInt32(4);

                                results.Add(new ProfileInfo(username, isAnonymous, lastActivityDate, lastUpdatedDate, size));
                            }
                        }
                    }
                }

                totalRecords = results.Count;
            }
            catch (SQLiteException ex)
            {
                if (WriteExceptionsToEventLog)
                    EventLogger.WriteToEventLog(ex, "GetAllProfiles");
                throw;
            }

            return results;
        }

        public override ProfileInfoCollection GetAllInactiveProfiles(ProfileAuthenticationOption authenticationOption,
            DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            var results = new ProfileInfoCollection();

            totalRecords = 0;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText =
                            "SELECT aspnet_Users.UserName, aspnet_Users.IsAnonymous, aspnet_Users.LastActivityDate, aspnet_Profile.LastUpdatedDate, DATALENGTH(aspnet_Profile.PropertyNames) + DATALENGTH(aspnet_Profile.PropertyValuesString) + DATALENGTH(aspnet_Profile.PropertyValuesBinary) " +
                            "FROM aspnet_Users, aspnet_Profile " +
                            "WHERE aspnet_Users.UserId = aspnet_Profile.UserId AND ApplicationId = @ApplicationId AND (@ProfileAuthOptions = 2 OR (@ProfileAuthOptions = 0 AND IsAnonymous = 1) OR (@ProfileAuthOptions = 1 AND IsAnonymous = 0)) AND (@InactiveSinceDate IS NULL OR aspnet_Users.LastActivityDate <= @InactiveSinceDate) " +
                            "ORDER BY aspnet_Users.UserName Asc " +
                            "LIMIT @PageSize OFFSET @PageStart";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@ProfileAuthOptions", (int) authenticationOption),
                            cmd.CreateParameter("@InactiveSinceDate", userInactiveSinceDate.ToUniversalTime()),
                            cmd.CreateParameter("@PageSize", pageSize),
                            cmd.CreateParameter("@PageStart", pageIndex*pageSize)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess))
                        {
                            while (reader.Read())
                            {
                                var username = reader.GetString(0);
                                var isAnonymous = reader.GetBoolean(1);
                                var lastActivityDate = DateTime.SpecifyKind(reader.GetDateTime(2), DateTimeKind.Utc);
                                var lastUpdatedDate = DateTime.SpecifyKind(reader.GetDateTime(3), DateTimeKind.Utc);
                                var size = reader.GetInt32(4);

                                results.Add(new ProfileInfo(username, isAnonymous, lastActivityDate, lastUpdatedDate, size));
                            }
                        }
                    }
                }

                totalRecords = results.Count;
            }
            catch (SQLiteException ex)
            {
                if (WriteExceptionsToEventLog)
                    EventLogger.WriteToEventLog(ex, "GetAllInactiveProfiles");
                throw;
            }

            return results;
        }

        public override ProfileInfoCollection FindProfilesByUserName(ProfileAuthenticationOption authenticationOption,
            string usernameToMatch,
            int pageIndex, int pageSize, out int totalRecords)
        {
            var results = new ProfileInfoCollection();

            totalRecords = 0;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText =
                            "SELECT aspnet_Users.UserName, aspnet_Users.IsAnonymous, aspnet_Users.LastActivityDate, aspnet_Profile.LastUpdatedDate, DATALENGTH(aspnet_Profile.PropertyNames) + DATALENGTH(aspnet_Profile.PropertyValuesString) + DATALENGTH(aspnet_Profile.PropertyValuesBinary) " +
                            "FROM aspnet_Users, aspnet_Profile " +
                            "WHERE aspnet_Users.UserId = aspnet_Profile.UserId AND ApplicationId = @ApplicationId AND (@ProfileAuthOptions = 2 OR (@ProfileAuthOptions = 0 AND IsAnonymous = 1) OR (@ProfileAuthOptions = 1 AND IsAnonymous = 0)) AND (@UserNameToMatch IS NULL OR LoweredUserName LIKE LOWER(@UserNameToMatch)) " +
                            "ORDER BY aspnet_Users.UserName Asc " +
                            "LIMIT @PageSize OFFSET @PageStart";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@ProfileAuthOptions", (int) authenticationOption),
                            cmd.CreateParameter("@UserNameToMatch", usernameToMatch),
                            cmd.CreateParameter("@PageSize", pageSize),
                            cmd.CreateParameter("@PageStart", pageIndex*pageSize)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess))
                        {
                            while (reader.Read())
                            {
                                var username = reader.GetString(0);
                                var isAnonymous = reader.GetBoolean(1);
                                var lastActivityDate = DateTime.SpecifyKind(reader.GetDateTime(2), DateTimeKind.Utc);
                                var lastUpdatedDate = DateTime.SpecifyKind(reader.GetDateTime(3), DateTimeKind.Utc);
                                var size = reader.GetInt32(4);

                                results.Add(new ProfileInfo(username, isAnonymous, lastActivityDate, lastUpdatedDate, size));
                            }
                        }
                    }
                }

                totalRecords = results.Count;
            }
            catch (SQLiteException ex)
            {
                if (WriteExceptionsToEventLog)
                    EventLogger.WriteToEventLog(ex, "FindProfilesByUserName");
                throw;
            }

            return results;
        }

        public override ProfileInfoCollection FindInactiveProfilesByUserName(
            ProfileAuthenticationOption authenticationOption,
            string usernameToMatch, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            var results = new ProfileInfoCollection();

            totalRecords = 0;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText =
                            "SELECT aspnet_Users.UserName, aspnet_Users.IsAnonymous, aspnet_Users.LastActivityDate, aspnet_Profile.LastUpdatedDate, DATALENGTH(aspnet_Profile.PropertyNames) + DATALENGTH(aspnet_Profile.PropertyValuesString) + DATALENGTH(aspnet_Profile.PropertyValuesBinary) " +
                            "FROM aspnet_Users, aspnet_Profile " +
                            "WHERE aspnet_Users.UserId = aspnet_Profile.UserId AND ApplicationId = @ApplicationId AND (@ProfileAuthOptions = 2 OR (@ProfileAuthOptions = 0 AND IsAnonymous = 1) OR (@ProfileAuthOptions = 1 AND IsAnonymous = 0)) AND (@InactiveSinceDate IS NULL OR aspnet_Users.LastActivityDate <= @InactiveSinceDate) AND (@UserNameToMatch IS NULL OR LoweredUserName LIKE LOWER(@UserNameToMatch))" +
                            "ORDER BY aspnet_Users.UserName Asc " +
                            "LIMIT @PageSize OFFSET @PageStart";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@ProfileAuthOptions", (int) authenticationOption),
                            cmd.CreateParameter("@UserNameToMatch", usernameToMatch),
                            cmd.CreateParameter("@InactiveSinceDate", userInactiveSinceDate.ToUniversalTime()),
                            cmd.CreateParameter("@PageSize", pageSize),
                            cmd.CreateParameter("@PageStart", pageIndex*pageSize)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess))
                        {
                            while (reader.Read())
                            {
                                var username = reader.GetString(0);
                                var isAnonymous = reader.GetBoolean(1);
                                var lastActivityDate = DateTime.SpecifyKind(reader.GetDateTime(2), DateTimeKind.Utc);
                                var lastUpdatedDate = DateTime.SpecifyKind(reader.GetDateTime(3), DateTimeKind.Utc);
                                var size = reader.GetInt32(4);

                                results.Add(new ProfileInfo(username, isAnonymous, lastActivityDate, lastUpdatedDate, size));
                            }
                        }
                    }
                }

                totalRecords = results.Count;
            }
            catch (SQLiteException ex)
            {
                if (WriteExceptionsToEventLog)
                    EventLogger.WriteToEventLog(ex, "FindInactiveProfilesByUserName");
                throw;
            }

            return results;
        }

        private string GetUserId(string userName)
        {
            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT UserId " +
                                          "FROM [aspnet_Users] " +
                                          "WHERE LOWER(@UserName) = LoweredUserName AND ApplicationId = @ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@UserName", userName),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        return cmd.ExecuteScalar() as string;
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "GetUserId");
            }

            return Guid.Empty.ToString();
        }

        private void GetPropertyValuesFromDatabase(string userName, SettingsPropertyValueCollection svc)
        {
            string[] names = null;
            string values = null;
            byte[] buf = null;
            
            using (var con = SQLiteUtils.GetConnection(_connectionString))
            {
                con.Open();

                string userId;

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "SELECT UserId " +
                                      "FROM [aspnet_Users] " +
                                      "WHERE ApplicationId = @ApplicationId AND LoweredUserName = LOWER(@UserName)";
                    cmd.Parameters.AddRange(new[]
                    {
                        cmd.CreateParameter("@ApplicationId", _applicationId),
                        cmd.CreateParameter("@UserName", userName)
                    });

                    userId = cmd.ExecuteScalar() as string;

                    if (userId == null)
                        return;
                }

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "SELECT PropertyNames, PropertyValuesString, PropertyValuesBinary " +
                                      "FROM aspnet_Profile " +
                                      "WHERE UserId = @UserId";
                    cmd.Parameters.Add(cmd.CreateParameter("@UserId", userId));

                    using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
                    {
                        if (reader.Read())
                        {
                            names = reader.GetString(0).Split(':');
                            values = reader.GetString(1);

                            var size = (int) reader.GetBytes(2, 0, null, 0, 0);

                            buf = new byte[size];

                            reader.GetBytes(2, 0, buf, 0, size);
                        }
                        ParseDataFromDb(names, values, buf, svc);
                    }
                }

                using (var cmd = con.CreateCommand())
                {
                    cmd.CommandText = "UPDATE [aspnet_Users] " +
                                      "SET LastActivityDate = @CurrentTimeUtc " +
                                      "WHERE UserId = @UserId";
                    cmd.Parameters.AddRange(new[]
                    {
                        cmd.CreateParameter("@CurrentTimeUtc", DateTime.UtcNow),
                        cmd.CreateParameter("@UserId", userId)
                    });

                    cmd.ExecuteNonQuery();
                }
            }
        }

        private void PrepareDataForSaving(ref string allNames, ref string allValues, ref byte[] buf,
            bool binarySupported, SettingsPropertyValueCollection properties, bool userIsAuthenticated)
        {
            try
            {
                var names = new StringBuilder();
                var values = new StringBuilder();

                using (var ms = (binarySupported ? new MemoryStream() : null))
                {

                    var anyItemsToSave = false;

                    foreach (
                        var pp in properties.Cast<SettingsPropertyValue>().Where(pp => pp.IsDirty))
                    {
                        if (!userIsAuthenticated)
                        {
                            var allowAnonymous = (bool) pp.Property.Attributes["AllowAnonymous"];
                            if (!allowAnonymous)
                                continue;
                        }
                        anyItemsToSave = true;
                        break;
                    }

                    if (!anyItemsToSave)
                        return;

                    foreach (SettingsPropertyValue pp in properties)
                    {
                        if (!userIsAuthenticated)
                        {
                            var allowAnonymous = (bool) pp.Property.Attributes["AllowAnonymous"];
                            if (!allowAnonymous)
                                continue;
                        }

                        if (!pp.IsDirty && pp.UsingDefaultValue) // Not fetched from DB and not written to
                            continue;

                        int len;
                        var startPos = 0;
                        string propValue = null;

                        if (pp.Deserialized && pp.PropertyValue == null) // is value null?
                        {
                            len = -1;
                        }
                        else
                        {
                            var sVal = pp.SerializedValue;

                            if (sVal == null)
                            {
                                len = -1;
                            }
                            else
                            {
                                if (!(sVal is string) && !binarySupported)
                                {
                                    sVal = Convert.ToBase64String((byte[]) sVal);
                                }

                                if (sVal is string)
                                {
                                    propValue = (string) sVal;
                                    len = propValue.Length;
                                    startPos = values.Length;
                                }
                                else
                                {
                                    var b2 = (byte[]) sVal;
                                    startPos = (int) ms.Position;
                                    ms.Write(b2, 0, b2.Length);
                                    ms.Position = startPos + b2.Length;
                                    len = b2.Length;
                                }
                            }
                        }

                        names.Append(pp.Name + ":" + ((propValue != null) ? "S" : "B") +
                                     ":" + startPos.ToString(CultureInfo.InvariantCulture) + ":" +
                                     len.ToString(CultureInfo.InvariantCulture) + ":");
                        if (propValue != null)
                            values.Append(propValue);
                    }

                    if (binarySupported)
                    {
                        buf = ms.ToArray();
                    }
                    allNames = names.ToString();
                    allValues = values.ToString();
                }
            }
            catch (Exception ex)
            {
                if(WriteExceptionsToEventLog)
                    EventLogger.WriteToEventLog(ex, "PrepareDataForSaving");
            }
        }

        private void ParseDataFromDb(string[] names, string values, byte[] buf, SettingsPropertyValueCollection properties)
        {
            if (names == null || values == null || buf == null || properties == null)
                return;

            try
            {
                for (var i = 0; i < names.Length / 4; i++)
                {
                    var name = names[i * 4];
                    var pp = properties[name];

                    if (pp == null) // property not found
                        continue;

                    var startPos = Int32.Parse(names[i * 4 + 2], CultureInfo.InvariantCulture);
                    var length = Int32.Parse(names[i * 4 + 3], CultureInfo.InvariantCulture);

                    if (length == -1 && !pp.Property.PropertyType.IsValueType) // Null Value
                    {
                        pp.PropertyValue = null;
                        pp.IsDirty = false;
                        pp.Deserialized = true;
                    }

                    if (names[i * 4 + 1] == "S" && startPos >= 0 && length > 0 && values.Length >= startPos + length)
                    {
                        pp.SerializedValue = values.Substring(startPos, length);
                    }

                    if (names[i * 4 + 1] == "B" && startPos >= 0 && length > 0 && buf.Length >= startPos + length)
                    {
                        var buf2 = new byte[length];

                        Buffer.BlockCopy(buf, startPos, buf2, 0, length);
                        pp.SerializedValue = buf2;
                    }
                }
            }
            catch(Exception ex)
            {
                if(WriteExceptionsToEventLog)
                    EventLogger.WriteToEventLog(ex, "ParseDataFromDb");
            }
        }
    }
}
