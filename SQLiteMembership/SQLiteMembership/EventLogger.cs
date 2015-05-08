using System;
using System.Diagnostics;

namespace SQLiteMembership
{
    static class EventLogger
    {
        public static void WriteToEventLog(Exception ex, string action)
        {
            var message = Constants.DatasourceExceptionMessage + "\n\n";
            message += "Action: " + action + "\n\n";
            message += "Exception: " + ex;

            using (var log = new EventLog())
            {
                log.Source = "ApplicationMembershipProvider";
                log.Log = "Application";
                log.WriteEntry(message);
            }
        }
    }
}
