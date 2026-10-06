
  SHERLOCK - a transaction-analysis assistant for investigating online financial crime
  (investment scams, romance scams, authorised push payment fraud, account takeover, etc).
 
  No external dependencies. Requires Java 11 or newer.
 
    Run:      java Sherlock.java <transactions.csv>             (interactive)
              java Sherlock.java <transactions.csv> analyze     (one-shot)
    Demo:     java Sherlock.java demo demo.csv   then   java Sherlock.java demo.csv
 
  CSV columns (header row required, order irrelevant, extra columns ignored):
    id, timestamp, from, to, amount            <- required
    currency, ip, device, memo                 <- optional but very useful
  Timestamps: ISO-8601 ("2026-03-02T09:00:00Z", "2026-03-02T09:00:00", "2026-03-02 09:00:00").
  Times without a zone are treated as UTC. "ip" and "device" describe the SENDER's session.
 
  IMPORTANT: Sherlock produces investigative LEADS, not proof. Every finding must be verified
  against original bank/provider records and handled under your force's evidence procedures.
 
