using System.Data;

namespace SQLiteMembership
{
    static class DbCommandExtensions
    {
        public static IDbDataParameter CreateParameter(this IDbCommand command, string parameterName, object value)
        {
            var parameter = command.CreateParameter();

            parameter.ParameterName = parameterName;
            parameter.Value = value;

            return parameter;
        }
    }
}
