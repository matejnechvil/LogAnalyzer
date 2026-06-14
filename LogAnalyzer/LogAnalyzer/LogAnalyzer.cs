using Microsoft.VisualBasic;

namespace LogAnalyzer
{
    internal class LogAnalyzer
    {
        private List<LogEntry> Entries;
        private List<string> KnownIPs;
        Dictionary<string, int> ErrorDict = new Dictionary<string, int>();
        Dictionary<string, List<DateTime>> BruteForceDict = new Dictionary<string, List<DateTime>>();
        Dictionary<string, string> bruteForceUsers = new Dictionary<string, string>();



        public List<Alert> Alerts { get; set; }

        public LogAnalyzer(List<LogEntry> Entries, List<string> KnownIPs)
        {
            this.Entries = Entries;
            this.KnownIPs = KnownIPs;
            Alerts = new List<Alert>();
        }

        public void Analyze()
        {
            for (int i = 0; i < Entries.Count; i++)
            {
                DetectLockedAccount(Entries[i]);
                DetectNightLogin(Entries[i]);
                DetectUnknownIPs(Entries[i]);
                DetectErrorRepetition(Entries[i], i);
                DetectBruteForce(Entries[i], i);
            }
            GetStatistics();
        }


        private void DetectLockedAccount(LogEntry oneEntry)
        {
            if (oneEntry.Event == "ACCOUNT_LOCKED")
            {
                Alert alert = new Alert
                {
                    Title = "ACCOUNT LOCKED",
                    AffectedUser = oneEntry.User,
                    Severity = oneEntry.Severity,
                    DescrIPtion = $"Account {oneEntry.User} on IP {oneEntry.IP} was locked out on {oneEntry.DateAndTime:yyyy.dd.MM} at {oneEntry.DateAndTime:HH:mm:ss}",
                    DateAndTime = oneEntry.DateAndTime,
                    IP = oneEntry.IP
                };

                Alerts.Add(alert);
            }
        }
        private void DetectNightLogin(LogEntry oneEntry)
        {
            int login;
            if (oneEntry.Event == "LOGIN_SUCCESS")
            {
                login = 1;
            }
            else if (oneEntry.Event == "LOGIN_FAIL")
            {
                login = 2;
            }
            else
            {
                login = 0;
            }

            if (login == 1 || login == 2)
            {
                if (oneEntry.DateAndTime.Hour > 21 || oneEntry.DateAndTime.Hour < 5)
                {
                    Alert alert = new Alert
                    {
                        Title = "NIGHT LOGIN",
                        AffectedUser = oneEntry.User,
                        Severity = oneEntry.Severity,
                        DescrIPtion = $"Account {oneEntry.User} on IP {oneEntry.IP} {(login == 1 ? "logged in" : "tried to log in")} outside of standard hours on {oneEntry.DateAndTime:yyyy.dd.MM} at {oneEntry.DateAndTime:HH:mm:ss}",
                        DateAndTime = oneEntry.DateAndTime,
                        IP = oneEntry.IP
                    };

                    Alerts.Add(alert);
                }
            }
        }

        private void DetectUnknownIPs(LogEntry oneEntry)
        {
            if (!KnownIPs.Contains(oneEntry.IP))
            {
                Alert alert = new Alert
                {
                    Title = "UNKNOWN IP ADRESS",
                    AffectedUser = oneEntry.User,
                    Severity = oneEntry.Severity,
                    DescrIPtion = $"Account {oneEntry.User} on IP {oneEntry.IP} is not in the list of trusted IP adresses",
                    DateAndTime = oneEntry.DateAndTime,
                    IP = oneEntry.IP
                };

                Alerts.Add(alert);
            }
        }

        private void DetectErrorRepetition(LogEntry oneEntry, int iteration)
        {
            if (oneEntry.Severity == "ERROR")
            {
                if (ErrorDict.ContainsKey(oneEntry.Event))
                {
                    ErrorDict[oneEntry.Event]++;
                }
                else
                {
                    ErrorDict.Add(oneEntry.Event, 1);
                }
            }

            if (iteration != Entries.Count - 1)
            {
                return;
            }

            foreach (var (errorName, count) in ErrorDict)
            {
                if (count > 2)
                {
                    Alert alert = new Alert
                    {
                        Title = "ERROR REPETITION",
                        AffectedUser = "NONE",
                        Severity = "ERROR",
                        DescrIPtion = $"Error {errorName} has repeated {count} times in the log",
                        DateAndTime = DateTime.MinValue,
                        IP = "NONE"
                    };

                    Alerts.Add(alert);
                }
            }
        }
        private void DetectBruteForce(LogEntry oneEntry, int iteration)
        {
            int timespan = 20;
            int loginCount = 5;

            if (oneEntry.Event == "LOGIN_FAIL")
            {
                if (!BruteForceDict.ContainsKey(oneEntry.IP)) {
                    BruteForceDict[oneEntry.IP] = new List<DateTime>();
                }
                BruteForceDict[oneEntry.IP].Add(oneEntry.DateAndTime);
                bruteForceUsers[oneEntry.IP] = oneEntry.User;
            }

            if (iteration != Entries.Count - 1)
            {
                return;
            }

            foreach (var item in BruteForceDict)
            {
                if (item.Value.Count > loginCount)
                {
                    bool bruteForce = true;
                    for (int i = 0; i < item.Value.Count - 1; i++)
                    {
                        TimeSpan secondsBetweenLogins = item.Value[i+1] - item.Value[i];
                        int seconds = (int)secondsBetweenLogins.TotalSeconds;

                        if (seconds > timespan )
                        {
                            bruteForce = false;
                        }
                    }

                    if (bruteForce)
                    {

                        Alert alert = new Alert
                        {
                            Title = "BRUTE FORCE ATTACK",
                            AffectedUser = bruteForceUsers[item.Key],
                            Severity = "ERROR",
                            DescrIPtion = $"BruteForce attack was detected on ip {oneEntry.IP} user/s {bruteForceUsers[item.Key]}... Login attemps: {item.Value.Count}",
                            DateAndTime = item.Value[item.Value.Count - 1],
                            IP = item.Key
                        };

                        Alerts.Add(alert);
                    }
                }
            }
        }

        private int CountAlertsByTitle(string title)
        {
            int count = 0;

            foreach (var a in Alerts)
            {
                if (a.Title == title)
                {
                    count++;
                }
            }
            return count;
        }

        public string GetStatistics()
        {
            return $@"
 Total entries: {Entries.Count};
 Total alerts: {Alerts.Count};
 - - - - - - - - - - - -
 Brute force detections: {CountAlertsByTitle("BRUTE FORCE ATTACK")}
 Accounts Locked: {CountAlertsByTitle("ACCOUNT LOCKED")};
 Unrecognized IPs: {CountAlertsByTitle("UNKNOWN IP ADRESS")};
 Night logins: {CountAlertsByTitle("NIGHT LOGIN")};
 Repeating errors: {CountAlertsByTitle("ERROR REPETITION")}
            ";
        }


    }
}
