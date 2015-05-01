using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data.SQLite;
using System.Linq;
using System.Web.Hosting;
using System.Web.Security;

namespace SQLiteMembership
{
    public sealed class SQLiteRoleProvider : RoleProvider
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
                name = "SQLiteRoleProvider";

            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "SQLite Role Provider");
            }

            base.Initialize(name, config);

            WriteExceptionsToEventLog = Convert.ToBoolean(config["writeExceptionsToEventLog"].DefaultIfEmpty("true"));
            ApplicationName = config["applicationName"].DefaultIfEmpty(HostingEnvironment.ApplicationVirtualPath);
            
            var connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];

            if (connectionStringSettings == null || string.IsNullOrWhiteSpace(connectionStringSettings.ConnectionString))
                throw new ProviderException("Connection string cannot be blank.");

            _connectionString = connectionStringSettings.ConnectionString;

            SQLiteMembershipUtils.CreateDatabaseIfRequired(_connectionString, ApplicationName);

            _applicationId = SQLiteMembershipUtils.GetApplicationId(_connectionString, ApplicationName);
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            var userIsInRole = false;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT COUNT(*) " +
                                          "FROM [aspnet_UsersInRoles] ur, [aspnet_Users] u, [aspnet_Roles] r " +
                                          "WHERE ur.UserId = u.UserId AND ur.RoleId = ar.RoleId AND u.UserName = @UserName AND r.RoleName = @RoleName";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@UserName", username),
                            cmd.CreateParameter("@RoleName", roleName),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        userIsInRole = (int) cmd.ExecuteScalar() > 0;                           
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "IsUserInRole");
            }

            return userIsInRole;
        }

        public override string[] GetRolesForUser(string username)
        {
            var roles = new List<string>();

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT RoleName " +
                                          "FROM [aspnet_Roles] r, [aspnet_UsersInRoles] ur " +
                                          "WHERE r.RoleId = ur.RoleId AND r.ApplicationId = @ApplicationId and ur.UserId = @UserId " +
                                          "ORDER BY RoleName";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@UserId", GetUserId(username)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                roles.Add(reader.GetString(0));
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "GetRolesForUser");
            }

            return roles.ToArray();
        }

        public override void CreateRole(string roleName)
        {
            try
            {
                if (roleName.IndexOf(',') > 0)
                    throw new ArgumentException("Role names cannot contain commas.");

                if (RoleExists(roleName))
                    throw new ProviderException("Role name already exists");

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "INSERT INTO [aspnet_Roles] (" +
                                          "RoleName, LoweredRoleName, ApplicationId" +
                                          ") VALUES ( " +
                                          "@Rolename, @LoweredRoleName, @ApplicationId" +
                                          ")";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@RoleName", roleName),
                            cmd.CreateParameter("@LoweredRoleName", roleName.ToLowerInvariant()),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "CreateRole");
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            try
            {
                if (!RoleExists(roleName))
                    throw new ProviderException("Role does not exist.");

                if (throwOnPopulatedRole && GetUsersInRole(roleName).Length > 0)
                    throw new ProviderException("Cannot delete a populated role.");

                var roleId = GetRoleId(roleName);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    using (var transaction = con.BeginTransaction())
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_UsersInRoles] " +
                                              "WHERE RoleId = @RoleId";
                            cmd.Parameters.Add(cmd.CreateParameter("@RoleId", roleId));

                            cmd.ExecuteNonQuery();
                        }

                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_Roles] " +
                                              "WHERE RoleId = @RoleId AND ApplicationId = @ApplicationId";
                            cmd.Parameters.AddRange(new[]
                            {
                                cmd.CreateParameter("@RoleId", roleId),
                                cmd.CreateParameter("@AppliationId", _applicationId)
                            });

                            cmd.ExecuteNonQuery();
                        }
                        transaction.Commit();
                    }
                }

                return true;
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "DeleteRole");
            }

            return false;
        }

        public override bool RoleExists(string roleName)
        {
            var roleExists = false;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT COUNT(*) " +
                                          "FROM [aspnet_Roles] " +
                                          "WHERE RoleName = @RoleName AND ApplicationId = @ApplicationId";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@RoleName", roleName),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        roleExists = (int) cmd.ExecuteScalar() > 0;
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "RoleExists");
            }

            return roleExists;
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            try
            {
                if (roleNames.Any(roleName => !RoleExists(roleName)))
                    throw new ProviderException("Role name not found.");

                foreach (var username in usernames)
                {
                    if (username.IndexOf(',') > 0)
                        throw new ArgumentException("Usernames cannot contain commas.");

                    if (roleNames.Any(roleName => IsUserInRole(username, roleName)))
                        throw new ProviderException("User is already in role.");
                }

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var transaction = con.BeginTransaction())
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "INSERT INTO [aspnet_UsersInRoles] (" +
                                              "UserId, RoleId" +
                                              ") VALUES (" +
                                              "@UserId, @RoleId" +
                                              ")";

                            foreach (var username in usernames)
                            {
                                foreach (var roleName in roleNames)
                                {
                                    cmd.Parameters.Clear();

                                    cmd.Parameters.AddRange(new []
                                    {
                                        cmd.CreateParameter("@UserId", GetUserId(username)),
                                        cmd.CreateParameter("@RoleId", GetRoleId(roleName))
                                    });

                                    cmd.ExecuteNonQuery();
                                }
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
                EventLogger.WriteToEventLog(ex, "AddUsersToRoles");
            }
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            try
            {
                if (roleNames.Any(x => !RoleExists(x)))
                    throw new ProviderException("Role name not found.");

                if (usernames.Any(username => roleNames.Any(roleName => !IsUserInRole(username, roleName))))
                    throw new ProviderException("User is not in role.");

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var transaction = con.BeginTransaction())
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_UsersInRoles] " +
                                              "WHERE UserId = @UserId AND RoleId = @RoleId";

                            foreach (var username in usernames)
                            {
                                foreach (var roleName in roleNames)
                                {
                                    cmd.Parameters.Clear();

                                    cmd.Parameters.AddRange(new[]
                                    {
                                        cmd.CreateParameter("@UserId", GetUserId(username)),
                                        cmd.CreateParameter("@RoleId", GetRoleId(roleName))
                                    });

                                    cmd.ExecuteNonQuery();
                                }
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
                EventLogger.WriteToEventLog(ex, "RemoveUsersFromRoles");
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            var roles = new List<string>();

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT u.UserName " +
                                          "FROM [aspnet_Users] u, [aspnet_UsersInRoles] ur " +
                                          "WHERE u.UserId = ur.UserId AND @RoleId = ur.RoleId AND u.ApplicationId = @ApplicationId " +
                                          "ORDER BY u.UserName";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@RoleId", GetRoleId(roleName)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                roles.Add(reader.GetString(0));
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "GetUsersInRole");
            }

            return roles.ToArray();
        }

        public override string[] GetAllRoles()
        {
            var roles = new List<string>();

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT RoleName " +
                                          "FROM [aspnet_Roles] " +
                                          "WHERE ApplicationId = @ApplicationId";
                        cmd.Parameters.Add(cmd.CreateParameter("@ApplicationId", _applicationId));

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                roles.Add(reader.GetString(0));
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "GetAllRoles");
            }

            return roles.ToArray();
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            var users = new List<string>();

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT u.UserName " +
                                          "FROM [aspnet_Users] u, [aspnet_UsersInRoles] ur " +
                                          "WHERE u.UserName LIKE @UserNameSearch AND ur.RoleName = @RoleName AND u.ApplicationId = @ApplicationId";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@UserNameSearch", usernameToMatch),
                            cmd.CreateParameter("@RoleName", roleName),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                users.Add(reader.GetString(0));
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                EventLogger.WriteToEventLog(ex, "FindUsersInRole");
            }

            return users.ToArray();
        }

        private string GetRoleId(string roleName)
        {
            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT RoleId " +
                                          "FROM [aspnet_Roles] " +
                                          "WHERE LOWER(@RoleName) = LoweredRoleName AND ApplicationId = @ApplicationId";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@RoleName", roleName),
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
                EventLogger.WriteToEventLog(ex, "GetRoleId");
            }

            return Guid.Empty.ToString();
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
    }
}
