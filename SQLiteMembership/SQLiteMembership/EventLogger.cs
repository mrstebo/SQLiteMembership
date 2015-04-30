using System;
using System.Diagnostics;

namespace SQLiteMembership
{
    static class EventLogger
    {
        public const string GenericExceptionMessage = "An exception occurred. Please check the Event Log.";

        public static void WriteToEventLog(Exception ex, string action)
        {
            var message = "An exception occurred communicating with the data source.\n\n";
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
