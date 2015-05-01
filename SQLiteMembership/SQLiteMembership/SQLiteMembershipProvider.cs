using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using System.Data.SQLite;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Web.Hosting;
using System.Web.Security;

namespace SQLiteMembership
{
    public sealed class SQLiteMembershipProvider : MembershipProvider
    {
        private bool _enablePasswordReset;
        private bool _enablePasswordRetrieval;
        private int _maxInvalidPasswordAttempts;
        private int _minRequiredNonAlphanumericCharacters;
        private int _minRequiredPasswordLength;
        private int _passwordAttemptWindow;
        private MembershipPasswordFormat _passwordFormat;
        private string _passwordStrengthRegularExpression;
        private bool _requiresQuestionAndAnswer;
        private bool _requiresUniqueEmail;
        private string _encryptionKey = "AE09F72BA97CBBB5EEAAFF";
        private string _connectionString;
        private string _applicationId;

        private const int SaltLength = 64;
        private const int NewPasswordLength = 12;

        public bool WriteExceptionsToEventLog { get; set; }

        public override string ApplicationName { get; set; }

        public override bool EnablePasswordReset
        {
            get { return _enablePasswordReset; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return _enablePasswordRetrieval; }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return _maxInvalidPasswordAttempts; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return _minRequiredNonAlphanumericCharacters; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return _minRequiredPasswordLength; }
        }

        public override int PasswordAttemptWindow
        {
            get { return _passwordAttemptWindow; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return _passwordFormat; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return _passwordStrengthRegularExpression; }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return _requiresQuestionAndAnswer; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return _requiresUniqueEmail; }
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            if (name.Length == 0)
                name = "SQLiteMembershipProvider";

            if (string.IsNullOrWhiteSpace(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "SQLite Membership Provider");
            }

            base.Initialize(name, config);

            WriteExceptionsToEventLog = Convert.ToBoolean(config["writeExceptionsToEventLog"].DefaultIfEmpty("true"));
            ApplicationName = config["applicationName"].DefaultIfEmpty(HostingEnvironment.ApplicationVirtualPath);

            _enablePasswordReset = Convert.ToBoolean(config["enablePasswordReset"].DefaultIfEmpty("true"));
            _enablePasswordRetrieval = Convert.ToBoolean(config["enablePasswordRetrieval"].DefaultIfEmpty("true"));
            _maxInvalidPasswordAttempts = Convert.ToInt32(config["maxInvalidPasswordAttempts"].DefaultIfEmpty("5"));
            _minRequiredNonAlphanumericCharacters = Convert.ToInt32(config["minRequiredNonAlphanumericCharacters"].DefaultIfEmpty("1"));
            _minRequiredPasswordLength = Convert.ToInt32(config["minRequiredPasswordLength"].DefaultIfEmpty("7"));
            _passwordAttemptWindow = Convert.ToInt32(config["passwordAttemptWindow"].DefaultIfEmpty("10"));
            _passwordStrengthRegularExpression = config["passwordStrengthRegularExpression"].DefaultIfEmpty("");
            _requiresQuestionAndAnswer = Convert.ToBoolean(config["requiredQuestionAndAnswer"].DefaultIfEmpty("false"));
            _requiresUniqueEmail = Convert.ToBoolean(config["requiresUniqueEmail"].DefaultIfEmpty("true"));
            _encryptionKey = config["encryptionKey"].DefaultIfEmpty(_encryptionKey);

            switch (config["passwordFormat"].DefaultIfEmpty("Hashed"))
            {
                case "Hashed":
                    _passwordFormat = MembershipPasswordFormat.Hashed;
                    break;

                case "Encrypted":
                    _passwordFormat = MembershipPasswordFormat.Hashed;
                    break;

                case "Clear":
                    _passwordFormat = MembershipPasswordFormat.Clear;
                    break;

                default:
                    throw new ProviderException("Password format not supported");
            }

            var connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];

            if (connectionStringSettings == null || string.IsNullOrWhiteSpace(connectionStringSettings.ConnectionString))
                throw new ProviderException("Connection string cannot be blank");

            _connectionString = connectionStringSettings.ConnectionString;

            SQLiteMembershipUtils.CreateDatabaseIfRequired(_connectionString, ApplicationName);

            _applicationId = SQLiteMembershipUtils.GetApplicationId(_connectionString, ApplicationName);
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            int rowsAffected;

            try
            {
                if (!ValidateUser(username, oldPassword))
                    return false;

                var args = new ValidatePasswordEventArgs(username, newPassword, true);

                OnValidatingPassword(args);

                if (args.Cancel)
                {
                    if (args.FailureInformation != null)
                        throw args.FailureInformation;
                    throw new MembershipPasswordException("Change password cancelled due to new password validation failure.");
                }

                var salt = GetSaltForUser(username);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                          "SET Password=@Password, LastPasswordChangedDate=@LastPasswordChangedDate " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@Password", EncodePassword(newPassword, salt)),
                            cmd.CreateParameter("@LastPasswordChangedDate", DateTime.UtcNow),
                            cmd.CreateParameter("@UserId", GetUserId(username)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        rowsAffected = cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "ChangePassword");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return rowsAffected > 0;
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            int rowsAffected;

            try
            {
                if (!ValidateUser(username, password))
                    return false;

                var salt = GetSaltForUser(username);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                          "SET PasswordQuestion=@Question, PasswordAnswer=@Answer " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@Question", newPasswordQuestion),
                            cmd.CreateParameter("@Answer", EncodePassword(newPasswordAnswer, salt)),
                            cmd.CreateParameter("@UserId", GetUserId(username)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        rowsAffected = cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "ChangePasswordQuestionAndAnswer");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return rowsAffected > 0;
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            try
            {
                var args = new ValidatePasswordEventArgs(username, password, true);

                OnValidatingPassword(args);

                if (args.Cancel)
                {
                    status = MembershipCreateStatus.InvalidPassword;
                    return null;
                }

                if (RequiresUniqueEmail && !string.IsNullOrWhiteSpace(GetUserNameByEmail(email)))
                {
                    status = MembershipCreateStatus.DuplicateEmail;
                    return null;
                }

                var membershipUser = GetUser(username, false);

                if (membershipUser != null)
                {
                    status = MembershipCreateStatus.DuplicateUserName;
                    return null;
                }
                var createDate = DateTime.UtcNow;

                if (providerUserKey == null)
                {
                    providerUserKey = Guid.NewGuid();
                }
                else
                {
                    if (!(providerUserKey is Guid))
                    {
                        status = MembershipCreateStatus.InvalidProviderUserKey;
                        return null;
                    }
                }

                passwordQuestion = string.IsNullOrWhiteSpace(passwordQuestion) ? string.Empty : passwordQuestion;
                passwordAnswer = string.IsNullOrWhiteSpace(passwordAnswer) ? string.Empty : passwordAnswer;
                
                var salt = GenerateSalt();

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var transaction = con.BeginTransaction())
                    {
                        int userRowsAffected;
                        int membershipRowsAffected;

                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "INSERT INTO [aspnet_Users] (" +
                                              "[ApplicationId]," +
                                              "[UserId]," +
                                              "[UserName]," +
                                              "[LoweredUserName]," +
                                              "[IsAnonymous]," +
                                              "[LastActivityDate]" +
                                              ") VALUES (" +
                                              "@ApplicationId," +
                                              "@UserId," +
                                              "@UserName," +
                                              "@LoweredUserName," +
                                              "@IsAnonymous," +
                                              "@LastActivityDate" +
                                              ")";
                            cmd.Parameters.AddRange(new[]
                            {
                                cmd.CreateParameter("@ApplicationId", _applicationId),
                                cmd.CreateParameter("@UserId", providerUserKey),
                                cmd.CreateParameter("@UserName", username),
                                cmd.CreateParameter("@LoweredUserName", username.ToLowerInvariant()),
                                cmd.CreateParameter("@IsAnonymous", false),
                                cmd.CreateParameter("@LastActivityDate", createDate)
                            });

                            userRowsAffected = cmd.ExecuteNonQuery();
                        }

                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "INSERT INTO [aspnet_Membership] (" +
                                              "[ApplicationId], " +
                                              "[UserId]," +
                                              "[Password]," +
                                              "[PasswordFormat]," +
                                              "[PasswordSalt]," +
                                              "[Email]," +
                                              "[LoweredEmail]," +
                                              "[PasswordQuestion]," +
                                              "[PasswordAnswer]," +
                                              "[IsApproved]," +
                                              "[IsLockedOut]," +
                                              "[CreateDate]," +
                                              "[LastLoginDate]," +
                                              "[LastPasswordChangedDate]," +
                                              "[LastLockoutDate]," +
                                              "[FailedPasswordAttemptCount]," +
                                              "[FailedPasswordAttemptWindowStart]," +
                                              "[FailedPasswordAnswerAttemptCount]," +
                                              "[FailedPasswordAnswerAttemptWindowStart]," +
                                              "[Comment]" +
                                              ") VALUES (" +
                                              "@ApplicationId," +
                                              "@UserId," +
                                              "@Password," +
                                              "@PasswordFormat," +
                                              "@PasswordSalt," +
                                              "@Email," +
                                              "@LoweredEmail," +
                                              "@PasswordQuestion," +
                                              "@PasswordAnswer," +
                                              "@IsApproved," +
                                              "@IsLockedOut," +
                                              "@CreateDate," +
                                              "@LastLoginDate," +
                                              "@LastPasswordChangedDate," +
                                              "@LastLockoutDate," +
                                              "@FailedPasswordAttemptCount," +
                                              "@FailedPasswordAttemptWindowStart," +
                                              "@FailedPasswordAnswerAttemptCount," +
                                              "@FailedPasswordAnswerAttemptWindowStart," +
                                              "@Comment" +
                                              ")";
                            cmd.Parameters.AddRange(new[]
                            {
                                cmd.CreateParameter("@ApplicationId", _applicationId),
                                cmd.CreateParameter("@UserId", providerUserKey),
                                cmd.CreateParameter("@Password", EncodePassword(password, salt)),
                                cmd.CreateParameter("@PasswordFormat", PasswordFormat.GetHashCode()),
                                cmd.CreateParameter("@PasswordSalt", salt),
                                cmd.CreateParameter("@Email", email ?? ""),
                                cmd.CreateParameter("@LoweredEmail", (email ?? "").ToLowerInvariant()),
                                cmd.CreateParameter("@PasswordQuestion", passwordQuestion),
                                cmd.CreateParameter("@PasswordAnswer", EncodePassword(passwordAnswer, salt)),
                                cmd.CreateParameter("@IsApproved", isApproved),
                                cmd.CreateParameter("@IsLockedOut", false),
                                cmd.CreateParameter("@CreateDate", createDate),
                                cmd.CreateParameter("@LastLoginDate", createDate),
                                cmd.CreateParameter("@LastPasswordChangedDate", createDate),
                                cmd.CreateParameter("@LastLockoutDate", DateTime.MinValue),
                                cmd.CreateParameter("@FailedPasswordAttemptCount", 0),
                                cmd.CreateParameter("@FailedPasswordAttemptWindowStart", DateTime.MinValue),
                                cmd.CreateParameter("@FailedPasswordAnswerAttemptCount", 0),
                                cmd.CreateParameter("@FailedPasswordAnswerAttemptWindowStart", DateTime.MinValue),
                                cmd.CreateParameter("@Comment", "")
                            });

                            membershipRowsAffected = cmd.ExecuteNonQuery();
                        }
   
                        if (userRowsAffected > 0 && membershipRowsAffected > 0)
                        {
                            status = MembershipCreateStatus.Success;
                            transaction.Commit();
                        }
                        else
                        {
                            status = MembershipCreateStatus.UserRejected;
                            transaction.Rollback();
                        }
                    }
                }
                return GetUser(username, false);
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;
                
                EventLogger.WriteToEventLog(ex, "CreateUser");

                status = MembershipCreateStatus.ProviderError;
            }

            return null;
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            var rowsAffected = 0;

            try
            {
                var userId = GetUserId(username);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var transaction = con.BeginTransaction())
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_UsersInRoles] " +
                                              "WHERE UserId=@UserId AND @ApplicationId=@ApplicationId";
                            cmd.Parameters.AddRange(new[]
                            {
                                cmd.CreateParameter("@UserId", userId),
                                cmd.CreateParameter("@ApplicationId", _applicationId)
                            });

                            rowsAffected += cmd.ExecuteNonQuery();
                        }

                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_Membership] " +
                                              "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                            cmd.Parameters.AddRange(new[]
                            {
                                cmd.CreateParameter("@UserId", userId),
                                cmd.CreateParameter("@ApplicationId", _applicationId)
                            });

                            rowsAffected += cmd.ExecuteNonQuery();
                        }

                        if (deleteAllRelatedData)
                        {
                            using (var cmd = con.CreateCommand())
                            {
                                cmd.CommandText = "DELETE FROM [aspnet_Profile] " +
                                                  "WHERE UserId=@userId";
                                cmd.Parameters.Add(cmd.CreateParameter("@UserId", userId));

                                rowsAffected += cmd.ExecuteNonQuery();
                            }
                        }

                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "DELETE FROM [aspnet_Users] " +
                                              "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                            cmd.Parameters.AddRange(new[]
                            {
                                cmd.CreateParameter("@UserId", userId),
                                cmd.CreateParameter("@ApplicationId", _applicationId)
                            });

                            rowsAffected += cmd.ExecuteNonQuery();
                        }

                        transaction.Commit();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "DeleteUser");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return rowsAffected > 0;
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = new MembershipUserCollection();

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT Count(*) " +
                                          "FROM [aspnet_Membership] " +
                                          "WHERE Email LIKE @EmailSearch AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@EmailSearch", emailToMatch),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        totalRecords = Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);

                        if (totalRecords <= 0)
                            return users;
                    }

                    using(var cmd = con.CreateCommand())
                    {
                        cmd.CommandText =
                            "SELECT m.UserId, u.Username, Email, PasswordQuestion, Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, LastLockoutDate " +
                            "FROM [aspnet_Membership] m, [aspnet_Users] u " +
                            "WHERE Email LIKE @EmailSearch AND m.ApplicationId=@ApplicationId AND m.UserId = u.UserId " +
                            "ORDER BY u.Username Asc " +
                            "LIMIT @PageSize OFFSET @PageStart";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@EmailSearch", emailToMatch),
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@PageSize", pageSize),
                            cmd.CreateParameter("@PageStart", pageIndex*pageSize) 
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                users.Add(GetUserFromRecord(reader));
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "FindUsersByEmail");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return users;
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = new MembershipUserCollection();

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT Count(*) " +
                                          "FROM [aspnet_Membership] " +
                                          "WHERE Email LIKE @UsernameSearch AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@UsernameSearch", usernameToMatch),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        totalRecords = Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);

                        if (totalRecords <= 0)
                            return users;
                    }

                    using(var cmd = con.CreateCommand())
                    {
                        cmd.CommandText =
                            "SELECT m.UserId, u.Username, Email, PasswordQuestion, Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, LastLockoutDate " +
                            "FROM [aspnet_Membership] m, [aspnet_Users] u " +
                            "WHERE u.Username LIKE @UsernameSearch ANDm.ApplicationId=@ApplicationId AND m.UserId = u.UserId " +
                            "ORDER BY u.Username Asc " +
                            "LIMIT @PageSize OFFSET @PageStart";

                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@UsernameSearch", usernameToMatch),
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@PageSize", pageSize),
                            cmd.CreateParameter("@PageStart", pageIndex*pageSize)
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                users.Add(GetUserFromRecord(reader));
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "FindUsersByName");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return users;
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            var users = new MembershipUserCollection();

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT Count(*) FROM [aspnet_Membership] " +
                                          "WHERE ApplicationId=@ApplicationId";
                        cmd.Parameters.Add(cmd.CreateParameter("@ApplicationId", _applicationId));

                        totalRecords = Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);

                        if (totalRecords <= 0)
                            return users;
                    }

                    using(var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT [aspnet_Membership].UserId, Username, Email, PasswordQuestion," +
                                          " Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate," +
                                          " LastActivityDate, LastPasswordChangedDate, LastLockoutDate " +
                                          " FROM [aspnet_Membership], [aspnet_Users] " +
                                          " WHERE [aspnet_Membership].ApplicationId=@ApplicationId " +
                                          " AND [aspnet_Membership].UserId = [aspnet_Users].UserId " +
                                          " ORDER BY Username Asc LIMIT @PageSize OFFSET @PageStart";

                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@PageSize", pageSize),
                            cmd.CreateParameter("@PageStart", pageIndex*pageSize)
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                users.Add(GetUserFromRecord(reader));
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "GetAllUsers");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return users;
        }

        public override int GetNumberOfUsersOnline()
        {
            int numUsersOnline;
            var onlineSpan = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
            var compareTime = DateTime.UtcNow.Subtract(onlineSpan);

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT Count(*) FROM [aspnet_Users] " +
                                          "WHERE LastActivityDate > @CompareDate AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@CompareDate", compareTime),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        numUsersOnline = Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "GetNumberOfUsersOnline");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return numUsersOnline;
        }

        public override string GetPassword(string username, string answer)
        {
            if (!EnablePasswordRetrieval)
                throw new ProviderException("Password Retrieval Not Enabled.");

            if (PasswordFormat == MembershipPasswordFormat.Hashed)
                throw new ProviderException("Cannot retrieve Hashed passwords.");

            string password;
            
            try
            {
                string passwordAnswer;
                string salt;

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText =
                            "SELECT Password, PasswordAnswer, PasswordSalt, IsLockedOut FROM [aspnet_Membership] " +
                            "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@UserId", GetUserId(username)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
                        {
                            if (!reader.Read())
                                throw new MembershipPasswordException("The supplied user name is not found.");

                            if (reader.GetBoolean(3))
                                throw new MembershipPasswordException("The supplied user is locked out.");

                            password = reader.GetString(0);
                            passwordAnswer = reader.GetString(1);
                            salt = reader.GetString(2);
                        }
                    }
                }

                if (RequiresQuestionAndAnswer && !CheckPassword(answer, passwordAnswer, salt))
                {
                    UpdateFailureCount(username, "passwordAnswer");

                    throw new MembershipPasswordException("Incorrect password answer.");
                }

                if (PasswordFormat == MembershipPasswordFormat.Encrypted)
                    password = UnEncodePassword(password);
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "GetPassword");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return password;
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            MembershipUser membershipUser = null;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT m.UserId, Username, Email, PasswordQuestion, Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, LastLockoutDate " +
                                          "FROM [aspnet_Membership] m, [aspnet_Users] u " +
                                          "WHERE Username=@Username AND m.ApplicationId=@ApplicationId AND m.UserId = u.UserId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@Username", username),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                membershipUser = GetUserFromRecord(reader);
                            }
                        }
                    }

                    if (membershipUser == null)
                        return null;

                    if (userIsOnline)
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "UPDATE [aspnet_Users] " +
                                              "SET LastActivityDate=@LastActivityDate " +
                                              "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                            cmd.Parameters.AddRange(new []
                            {
                                cmd.CreateParameter("@LastActivityDate", DateTime.UtcNow),
                                cmd.CreateParameter("@UserId", membershipUser.ProviderUserKey),
                                cmd.CreateParameter("@ApplicationId", _applicationId)
                            });

                            cmd.ExecuteNonQuery();
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "GetUser(String, Boolean)");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return membershipUser;
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            MembershipUser membershipUser = null;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT m.UserId, Username, Email, PasswordQuestion, " +
                                          "Comment, IsApproved, IsLockedOut, CreateDate, LastLoginDate, " +
                                          "LastActivityDate, LastPasswordChangedDate, LastLockoutDate " +
                                          "FROM [aspnet_Membership] m, [aspnet_Users] u " +
                                          "WHERE m.UserId=@UserId AND m.UserId = u.UserId";
                        cmd.Parameters.Add(cmd.CreateParameter("@UserId", providerUserKey));
                        
                        using (var reader = cmd.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                membershipUser = GetUserFromRecord(reader);
                            }
                        }
                    }

                    if (userIsOnline)
                    {
                        using (var cmd = con.CreateCommand())
                        {
                            cmd.CommandText = "UPDATE [aspnet_Users] " +
                                              "SET LastActivityDate=@LastActivityDate " +
                                              "WHERE UserId=@UserId";
                            cmd.Parameters.AddRange(new []
                            {
                                cmd.CreateParameter("@LastActivityDate", DateTime.UtcNow),
                                cmd.CreateParameter("@UserId", providerUserKey)
                            });
                            
                            cmd.ExecuteNonQuery();
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "GetUser(Object, Boolean)");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return membershipUser;
        }

        public override string GetUserNameByEmail(string email)
        {
            var username = "";

            try
            {
                if (string.IsNullOrWhiteSpace(email))
                    return string.Empty;

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT Username " +
                                          "FROM [aspnet_Users] u, [aspnet_Membership] m " +
                                          "WHERE Email=@Email AND m.ApplicationId=@ApplicationId AND m.UserId = u.UserId ";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@Email", email),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        var result = cmd.ExecuteScalar();
                        if (result != null) 
                            username = Convert.ToString(result, CultureInfo.InvariantCulture);
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "GetUserNameByEmail");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return username;
        }

        public override string ResetPassword(string username, string answer)
        {
            try
            {
                if (!EnablePasswordReset)
                    throw new NotSupportedException("Password reset is not enabled.");

                if (answer == null && RequiresQuestionAndAnswer)
                {
                    UpdateFailureCount(username, "passwordAnswer");

                    throw new ProviderException("Password answer required for password reset.");
                }

                var newPassword = Membership.GeneratePassword(NewPasswordLength, MinRequiredNonAlphanumericCharacters);
                var args = new ValidatePasswordEventArgs(username, newPassword, true);

                OnValidatingPassword(args);

                if (args.Cancel)
                {
                    if (args.FailureInformation != null)
                        throw args.FailureInformation;
                    throw new MembershipPasswordException("Reset password canceled due to password validation failure.");
                }

                var salt = GetSaltForUser(username);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT PasswordAnswer, IsLockedOut " +
                                          "FROM [aspnet_Membership] " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@UserId", GetUserId(username)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
                        {
                            if (!reader.Read())
                                throw new MembershipPasswordException("The supplied user name is not found.");

                            if (Convert.ToBoolean(reader.GetValue(1)))
                                throw new MembershipPasswordException("The supplied user is locked out.");

                            var passwordAnswer = reader.GetString(0);

                            if (RequiresQuestionAndAnswer && !CheckPassword(answer, passwordAnswer, salt))
                            {
                                UpdateFailureCount(username, "passwordAnswer");

                                throw new MembershipPasswordException("Incorrect password answer.");
                            }
                        }
                    }

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                          "SET Password=@Password, LastPasswordChangedDate=@LastPasswordChangedDate " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId AND IsLockedOut = 0";
                        cmd.Parameters.AddRange(new []
                        {
                            cmd.CreateParameter("@Password", EncodePassword(newPassword, salt)),
                            cmd.CreateParameter("@LastPasswordChangedDate", DateTime.UtcNow),
                            cmd.CreateParameter("@UserId", GetUserId(username)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        if(cmd.ExecuteNonQuery() <= 0)
                            throw new MembershipPasswordException("User not found, or user is locked out. Password not Reset.");
                        return newPassword;
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "ResetPassword");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }
        }

        public override bool UnlockUser(string userName)
        {
            int rowsAffected;

            try
            {
                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                          "SET IsLockedOut = 0, LastLockoutDate=@LastLockedOutDate " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@LastLockedOutDate", DateTime.UtcNow),
                            cmd.CreateParameter("@UserId", GetUserId(userName)),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        rowsAffected = cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "UnlockUser");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }

            return rowsAffected > 0;
        }

        public override void UpdateUser(MembershipUser user)
        {
            try
            {
                if (RequiresUniqueEmail)
                {
                    var userName = GetUserNameByEmail(user.Email);

                    if (!string.IsNullOrWhiteSpace(userName) &&
                        !userName.Equals(user.UserName, StringComparison.InvariantCultureIgnoreCase))
                        throw new ProviderException(
                            "The e-mail address that you entered is already in use. Please enter a different e-mail address.");
                }

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                          "SET Email=@Email, LoweredEmail=@LoweredEmail, Comment=@Comment, IsApproved=@IsApproved, LastLoginDate=@LastLoginDate " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@Email", user.Email),
                            cmd.CreateParameter("@LoweredEmail", (user.Email ?? "").ToLowerInvariant()),
                            cmd.CreateParameter("@Comment", user.Comment),
                            cmd.CreateParameter("@IsApproved", user.IsApproved),
                            cmd.CreateParameter("@UserId", user.ProviderUserKey),
                            cmd.CreateParameter("@LastLoginDate", user.LastLoginDate),
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

                EventLogger.WriteToEventLog(ex, "UpdateUser");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }
        }

        public override bool ValidateUser(string username, string password)
        {
            var isValid = false;

            try
            {
                var userId = GetUserId(username);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    bool isApproved;
                    string pwd;
                    string salt;

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT Password, PasswordSalt, IsApproved " +
                                          "FROM [aspnet_Membership] " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId AND IsLockedOut = 0";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@UserId", userId),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
                        {
                            if (!reader.Read())
                                return false;
                            
                            pwd = reader.GetString(0);
                            salt = reader.GetString(1);
                            isApproved = reader.GetBoolean(2);
                        }
                    }

                    if (CheckPassword(password, pwd, salt))
                    {
                        if (!isApproved)
                        {
                            UpdateFailureCount(username, "password");
                        }
                        else
                        {
                            isValid = true;

                            using (var cmd = con.CreateCommand())
                            {
                                cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                                  "SET LastLoginDate=@LastLoginDate " +
                                                  "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                                cmd.Parameters.AddRange(new []
                                {
                                    cmd.CreateParameter("@LastLoginDate", DateTime.UtcNow),
                                    cmd.CreateParameter("@UserId", userId),
                                    cmd.CreateParameter("@ApplicationId", _applicationId)
                                });

                                cmd.ExecuteNonQuery();
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "ValidateUser");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }
            return isValid;
        }

        private MembershipUser GetUserFromRecord(IDataRecord reader)
        {
            if (string.IsNullOrWhiteSpace(reader.GetString(1))) 
                return null;

            var strGooid = Guid.NewGuid().ToString();
            var providerUserKey = reader.GetValue(0).ToString().Length > 0 
                ? new Guid(reader.GetValue(0).ToString()) 
                : new Guid(strGooid);
            var username = reader.GetString(1);
            var email = reader.IsDBNull(2) ? null : reader.GetString(2);
            var passwordQuestion = reader.IsDBNull(3) ? string.Empty : reader.GetString(3);
            var comment = reader.IsDBNull(4) ? string.Empty : reader.GetString(4);
            var isApproved = !reader.IsDBNull(5) && reader.GetBoolean(5);
            var isLockedOut = !reader.IsDBNull(6) && reader.GetBoolean(6);
            var creationDate = reader.IsDBNull(7) ? DateTime.UtcNow : reader.GetDateTime(7);
            var lastLoginDate = reader.IsDBNull(8) ? DateTime.UtcNow : reader.GetDateTime(8);
            var lastActivityDate = reader.IsDBNull(9) ? DateTime.UtcNow : reader.GetDateTime(9);
            var lastPasswordChangedDate = reader.IsDBNull(10) ? DateTime.UtcNow : reader.GetDateTime(10);
            var lastLockedOutDate = reader.IsDBNull(11) ? DateTime.UtcNow : reader.GetDateTime(11);
            var membershipUser = new MembershipUser(
                Name,
                username,
                providerUserKey,
                email,
                passwordQuestion,
                comment,
                isApproved,
                isLockedOut,
                creationDate,
                lastLoginDate,
                lastActivityDate,
                lastPasswordChangedDate,
                lastLockedOutDate);

            return membershipUser;
        }

        private void UpdateFailureCount(string username, string failureType)
        {
            try
            {
                var userId = GetUserId(username);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    var windowStart = new DateTime();
                    var failureCount = 0;

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT FailedPasswordAttemptCount, FailedPasswordAttemptWindowStart, FailedPasswordAnswerAttemptCount, FailedPasswordAnswerAttemptWindowStart " +
                                          "FROM [aspnet_Membership] " +
                                          "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@UserId", userId),
                            cmd.CreateParameter("@ApplicationId", _applicationId)
                        });

                        using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
                        {
                            if (reader.Read())
                            {
                                switch (failureType)
                                {
                                    case "password":
                                        failureCount = reader.GetInt32(0);
                                        try
                                        {
                                            windowStart = reader.GetDateTime(1);
                                        }
                                        catch
                                        {
                                            windowStart = DateTime.UtcNow;
                                        }
                                        break;

                                    case "passwordAnswer":
                                        failureCount = reader.GetInt32(2);
                                        windowStart = reader.GetDateTime(3);
                                        break;
                                }
                            }
                        }
                    }

                    var windowEnd = windowStart.AddMinutes(PasswordAttemptWindow);

                    using (var cmd = con.CreateCommand())
                    {
                        if (failureCount == 0 || DateTime.UtcNow > windowEnd)
                        {
                            // First password failure or outside of PasswordAttemptWindow. 
                            // Start a new password failure count from 1 and a new window starting now.

                            if (failureType == "password")
                                cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                                  "SET FailedPasswordAttemptCount=@Count, FailedPasswordAttemptWindowStart=@WindowStart " +
                                                  "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";

                            if (failureType == "passwordAnswer")
                                cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                                  "SET FailedPasswordAnswerAttemptCount=@Count, FailedPasswordAnswerAttemptWindowStart=@WindowStart " +
                                                  "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";

                            cmd.Parameters.AddRange(new[]
                            {
                                cmd.CreateParameter("@Count", 1),
                                cmd.CreateParameter("@WindowStart", DateTime.UtcNow),
                                cmd.CreateParameter("@UserId", userId),
                                cmd.CreateParameter("@ApplicationId", _applicationId)
                            });

                            if (cmd.ExecuteNonQuery() < 0)
                                throw new ProviderException("Unable to update failure count and window start.");
                        }
                        else
                        {
                            if (failureCount++ >= MaxInvalidPasswordAttempts)
                            {
                                // Password attempts have exceeded the failure threshold. 
                                // Lock out the user.

                                cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                                  "SET IsLockedOut=@IsLockedOut, LastLockoutDate=@LastLockedOutDate " +
                                                  "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";

                                cmd.Parameters.AddRange(new[]
                                {
                                    cmd.CreateParameter("@IsLockedOut", true),
                                    cmd.CreateParameter("@LastLockedOutDate", DateTime.UtcNow),
                                    cmd.CreateParameter("@UserId", userId),
                                    cmd.CreateParameter("@ApplicationId", _applicationId)
                                });

                                if (cmd.ExecuteNonQuery() < 0)
                                    throw new ProviderException("Unable to lock out user.");
                            }
                            else
                            {
                                // Password attempts have not exceeded the failure threshold. 
                                // Update the failure counts. 
                                // Leave the window the same.

                                if (failureType == "password")
                                    cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                                      "SET FailedPasswordAttemptCount=@Count " +
                                                      "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";

                                if (failureType == "passwordAnswer")
                                    cmd.CommandText = "UPDATE [aspnet_Membership] " +
                                                      "SET FailedPasswordAnswerAttemptCount=@Count " +
                                                      "WHERE UserId=@UserId AND ApplicationId=@ApplicationId";

                                cmd.Parameters.AddRange(new []
                                {
                                    cmd.CreateParameter("@Count", failureCount),
                                    cmd.CreateParameter("@UserId", userId),
                                    cmd.CreateParameter("@ApplicationId", _applicationId)
                                });

                                if (cmd.ExecuteNonQuery() < 0)
                                    throw new ProviderException("Unable to update failure count.");
                            }
                        }
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "UpdateFailureCount");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }
        }

        private bool CheckPassword(string password, string dbpassword, string salt)
        {
            var pass1 = password;
            var pass2 = dbpassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Encrypted:
                    pass2 = UnEncodePassword(dbpassword);
                    break;

                case MembershipPasswordFormat.Hashed:
                    pass1 = EncodePassword(password, salt);
                    break;
            }

            return pass1 == pass2;
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
                                          "WHERE LOWER(@UserName) = LoweredUserName AND ApplicationId=@ApplicationId";
                        cmd.Parameters.AddRange(new []
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

        private string GetSaltForUser(string username)
        {
            try
            {
                var userId = GetUserId(username);

                using (var con = SQLiteUtils.GetConnection(_connectionString))
                {
                    con.Open();

                    using (var cmd = con.CreateCommand())
                    {
                        cmd.CommandText = "SELECT PasswordSalt " +
                                          "FROM [aspnet_Membership] " +
                                          "WHERE ApplicationId=@ApplicationId AND UserId=@UserId";
                        cmd.Parameters.AddRange(new[]
                        {
                            cmd.CreateParameter("@ApplicationId", _applicationId),
                            cmd.CreateParameter("@UserId", userId)
                        });

                        return cmd.ExecuteScalar() as string;
                    }
                }
            }
            catch (SQLiteException ex)
            {
                if (!WriteExceptionsToEventLog)
                    throw;

                EventLogger.WriteToEventLog(ex, "GetSaltForUser");

                throw new ProviderException(EventLogger.GenericExceptionMessage);
            }
        }

        private string EncodePassword(string password, string salt)
        {
            if (password == null) 
                password = "";
            
            var encodedPassword = password;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;

                case MembershipPasswordFormat.Encrypted:
                    var passBytes = Encoding.Unicode.GetBytes(password);
                    var saltBytes = Convert.FromBase64String(salt);
                    var allBytes = new byte[saltBytes.Length + passBytes.Length];
                    Buffer.BlockCopy(saltBytes, 0, allBytes, 0, saltBytes.Length);
                    Buffer.BlockCopy(passBytes, 0, allBytes, saltBytes.Length, passBytes.Length);
                    encodedPassword = Convert.ToBase64String(EncryptPassword(allBytes));
                    break;

                case MembershipPasswordFormat.Hashed:
                    using (var hash = new HMACSHA1())
                    {
                        hash.Key = (salt.IndexOfAny("=+/".ToCharArray()) > -1)
                            ? Convert.FromBase64String(salt)
                            : HexToByte(salt);
                        encodedPassword = Convert.ToBase64String(hash.ComputeHash(Encoding.Unicode.GetBytes(password)));
                    }
                    break;

                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return (encodedPassword.Length > 128) ? encodedPassword.Substring(0, 128) : encodedPassword;
        }

        private string UnEncodePassword(string encodedPassword)
        {
            var password = encodedPassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;

                case MembershipPasswordFormat.Encrypted:
                    byte[] allBytes = Convert.FromBase64String(password);
                    byte[] decryptedBytes = DecryptPassword(allBytes);
                    password = (decryptedBytes == null) ? null :
                        Encoding.Unicode.GetString(decryptedBytes, SaltLength, decryptedBytes.Length - SaltLength);
                    break;

                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException("Cannot decode a hashed password.");

                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return password;
        }

        private static string GenerateSalt()
        {
            var saltBytes = new byte[SaltLength];

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(saltBytes);
            }

            var salt = Convert.ToBase64String(saltBytes);

            return (salt.Length > 128) ? salt.Substring(0, 128) : salt;
        }

        private static byte[] HexToByte(string hexString)
        {
            var returnBytes = new byte[hexString.Length / 2];

            for (var i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);

            return returnBytes;
        }
    }
}
