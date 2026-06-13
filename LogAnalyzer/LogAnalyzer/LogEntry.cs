namespace LogAnalyzer
{
    internal class LogEntry
    {
        public required DateTime DateAndTime { get; set; }
        public required string Severity { get; set; }
        public required string Host { get; set; }
        public required string User { get; set; }
        public required string Event { get; set; }
        public required string IP { get; set; }
        public required int Port { get; set; }
        public required string Service { get; set; }
    }
}
