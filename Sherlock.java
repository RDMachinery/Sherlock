import java.io.*;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SHERLOCK - a transaction-analysis assistant for investigating online financial crime
 * (investment scams, romance scams, authorised push payment fraud, account takeover, etc).
 *
 * No external dependencies. Requires Java 11 or newer.
 *
 *   Run:      java Sherlock.java <transactions.csv>             (interactive)
 *             java Sherlock.java <transactions.csv> analyze     (one-shot)
 *   Demo:     java Sherlock.java demo demo.csv   then   java Sherlock.java demo.csv
 *
 * CSV columns (header row required, order irrelevant, extra columns ignored):
 *   id, timestamp, from, to, amount            <- required
 *   currency, ip, device, memo                 <- optional but very useful
 * Timestamps: ISO-8601 ("2026-03-02T09:00:00Z", "2026-03-02T09:00:00", "2026-03-02 09:00:00").
 * Times without a zone are treated as UTC. "ip" and "device" describe the SENDER's session.
 *
 * IMPORTANT: Sherlock produces investigative LEADS, not proof. Every finding must be verified
 * against original bank/provider records and handled under your force's evidence procedures.
 */
public class Sherlock {

    // ------------------------------------------------------------------
    // Tunable thresholds (change at runtime with:  set <name> <value>)
    // ------------------------------------------------------------------
    static double structThreshold = 10_000;   // reporting threshold that structuring tries to stay under
    static int structMin = 3;                 // min # of near-threshold payments to flag
    static int structWindowHours = 72;
    static double passRatio = 0.90;           // share of incoming money forwarded onward
    static double passMinTotal = 1_000;       // ignore tiny accounts
    static int passDwellHours = 48;           // avg time money sits before moving on
    static int fanMin = 5;                    // distinct counterparties inside the window
    static int fanWindowDays = 7;
    static int sharedDeviceMin = 2;           // accounts sharing one device
    static int sharedIpMin = 3;               // accounts sharing one IP (weaker: NAT, cafes, VPNs)
    static int cycleMaxLen = 4;

    // ------------------------------------------------------------------
    // Model
    // ------------------------------------------------------------------
    static final class Tx {
        final int line;
        final String id, from, to, currency, ip, device, memo;
        final Instant time;
        final BigDecimal amount;

        Tx(int line, String id, Instant time, String from, String to, BigDecimal amount,
           String currency, String ip, String device, String memo) {
            this.line = line; this.id = id; this.time = time; this.from = from; this.to = to;
            this.amount = amount; this.currency = currency; this.ip = ip; this.device = device;
            this.memo = memo;
        }

        double amt() { return amount.doubleValue(); }
    }

    static final class Finding {
        final String account, type, detail;
        final int weight;

        Finding(String account, String type, int weight, String detail) {
            this.account = account; this.type = type; this.weight = weight; this.detail = detail;
        }
    }

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------
    static final List<Tx> txs = new ArrayList<>();
    static final Map<String, List<Tx>> inBy = new HashMap<>();   // account -> incoming (time-sorted)
    static final Map<String, List<Tx>> outBy = new HashMap<>();  // account -> outgoing (time-sorted)
    static final List<String> warnings = new ArrayList<>();
    static String fileName = "", fileHash = "";
    static PrintStream out = System.out;

    static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneOffset.UTC);

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------
    public static void main(String[] args) throws Exception {
        if (args.length == 0) { usage(); return; }
        if (args[0].equalsIgnoreCase("demo")) {
            Path p = Paths.get(args.length > 1 ? args[1] : "demo.csv");
            writeDemo(p);
            System.out.println("Demo case written to " + p
                    + "\nTry:  java Sherlock.java " + p + "\nThen: trace ACC-VICTIM-01");
            return;
        }
        load(Paths.get(args[0]));
        if (args.length > 1) run(Arrays.copyOfRange(args, 1, args.length));
        else shell();
    }

    static void usage() {
        out.println(String.join("\n",
                "",
                "SHERLOCK - financial crime investigation assistant",
                "",
                "  summary                       overview of the loaded data + file SHA-256 (chain of custody)",
                "  analyze                       run all detectors, rank suspicious accounts",
                "  links                         clusters of accounts linked by shared device / IP",
                "  trace <account> [since]       follow the victim's outgoing money forward; shows where it is NOW",
                "  tracetx <txid> [txid...]      same, but starting from specific fraudulent payments",
                "  timeline <account>            chronological in/out history with running net position",
                "  account <account>             profile of one account (counterparties, IPs, devices, findings)",
                "  report <file> [victimAcct]    write a full text report (optionally with a trace)",
                "  set <name> <value>            change thresholds: threshold structmin structwindow passratio",
                "                                passmin dwell fanmin fanwindow devicemin ipmin cyclelen",
                "  help | quit",
                "",
                "Start with:   java Sherlock.java <file.csv>      Demo data: java Sherlock.java demo demo.csv",
                ""));
    }

    // ------------------------------------------------------------------
    // Interactive shell / dispatcher
    // ------------------------------------------------------------------
    static void shell() throws IOException {
        out.println("\nSHERLOCK ready. Type 'help' for commands, 'quit' to leave.\n");
        summary();
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.print("\nsherlock> ");
            System.out.flush();
            String line = br.readLine();
            if (line == null) break;
            line = line.trim();
            if (line.isEmpty()) continue;
            if (line.equalsIgnoreCase("quit") || line.equalsIgnoreCase("exit")) break;
            try { run(line.split("\\s+")); }
            catch (Exception e) { out.println("Error: " + e.getMessage()); }
        }
    }

    static void run(String[] a) throws Exception {
        switch (a[0].toLowerCase()) {
            case "help": usage(); break;
            case "summary": summary(); break;
            case "analyze": analyze(); break;
            case "links": links(); break;
            case "trace": {
                need(a, 2, "trace <account> [since-timestamp]");
                requireAccount(a[1]);
                Instant since = a.length > 2 ? parseTime(a[2]) : Instant.MIN;
                List<Tx> seeds = outBy.getOrDefault(a[1], List.of()).stream()
                        .filter(t -> !t.time.isBefore(since)).collect(Collectors.toList());
                trace(seeds, "all payments out of " + a[1] + (a.length > 2 ? " since " + a[2] : ""));
                break;
            }
            case "tracetx": {
                need(a, 2, "tracetx <txid> [txid...]");
                List<Tx> seeds = new ArrayList<>();
                for (int i = 1; i < a.length; i++) {
                    final String id = a[i];
                    Tx t = txs.stream().filter(x -> x.id.equals(id)).findFirst().orElse(null);
                    if (t == null) out.println("No transaction with id " + id); else seeds.add(t);
                }
                trace(seeds, "transactions " + String.join(", ", Arrays.copyOfRange(a, 1, a.length)));
                break;
            }
            case "timeline": need(a, 2, "timeline <account>"); requireAccount(a[1]); timeline(a[1]); break;
            case "account": need(a, 2, "account <account>"); requireAccount(a[1]); account(a[1]); break;
            case "report": {
                need(a, 2, "report <file> [victimAccount]");
                report(Paths.get(a[1]), a.length > 2 ? a[2] : null);
                break;
            }
            case "set": need(a, 3, "set <name> <value>"); setParam(a[1].toLowerCase(), a[2]); break;
            default: out.println("Unknown command '" + a[0] + "'. Type 'help'.");
        }
    }

    static void need(String[] a, int n, String usage) {
        if (a.length < n) throw new IllegalArgumentException("usage: " + usage);
    }

    static void requireAccount(String acct) {
        if (!accounts().contains(acct))
            throw new IllegalArgumentException("account '" + acct + "' not found in the data (names are case-sensitive)");
    }

    static void setParam(String n, String v) {
        switch (n) {
            case "threshold": structThreshold = Double.parseDouble(v); break;
            case "structmin": structMin = Integer.parseInt(v); break;
            case "structwindow": structWindowHours = Integer.parseInt(v); break;
            case "passratio": passRatio = Double.parseDouble(v); break;
            case "passmin": passMinTotal = Double.parseDouble(v); break;
            case "dwell": passDwellHours = Integer.parseInt(v); break;
            case "fanmin": fanMin = Integer.parseInt(v); break;
            case "fanwindow": fanWindowDays = Integer.parseInt(v); break;
            case "devicemin": sharedDeviceMin = Integer.parseInt(v); break;
            case "ipmin": sharedIpMin = Integer.parseInt(v); break;
            case "cyclelen": cycleMaxLen = Integer.parseInt(v); break;
            default: out.println("Unknown setting '" + n + "'. See 'help'."); return;
        }
        out.println("OK: " + n + " = " + v);
    }

    // ------------------------------------------------------------------
    // Loading & parsing
    // ------------------------------------------------------------------
    static void load(Path p) throws Exception {
        byte[] raw = Files.readAllBytes(p);
        fileName = p.getFileName().toString();
        fileHash = sha256(raw);
        String text = new String(raw, StandardCharsets.UTF_8);
        if (text.startsWith("\uFEFF")) text = text.substring(1);
        String[] lines = text.split("\\r?\\n");
        if (lines.length < 2) throw new IOException("File has no data rows.");

        String[] head = splitCsv(lines[0]);
        Map<String, Integer> col = new HashMap<>();
        for (int i = 0; i < head.length; i++) col.put(head[i].trim().toLowerCase(), i);
        for (String req : new String[]{"id", "timestamp", "from", "to", "amount"})
            if (!col.containsKey(req)) throw new IOException("Missing required column: " + req);

        Set<String> seenIds = new HashSet<>();
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].trim().isEmpty()) continue;
            try {
                String[] f = splitCsv(lines[i]);
                String id = get(f, col, "id");
                String from = get(f, col, "from"), to = get(f, col, "to");
                if (id.isEmpty() || from.isEmpty() || to.isEmpty()) throw new IllegalArgumentException("blank id/from/to");
                if (!seenIds.add(id)) throw new IllegalArgumentException("duplicate id " + id);
                BigDecimal amt = new BigDecimal(get(f, col, "amount").replaceAll("[^0-9.\\-]", ""));
                if (amt.signum() <= 0) throw new IllegalArgumentException("non-positive amount");
                txs.add(new Tx(i + 1, id, parseTime(get(f, col, "timestamp")), from, to, amt,
                        get(f, col, "currency").toUpperCase(), get(f, col, "ip"),
                        get(f, col, "device"), get(f, col, "memo")));
            } catch (Exception e) {
                warnings.add("line " + (i + 1) + " skipped: " + e.getMessage());
            }
        }
        txs.sort(Comparator.comparing((Tx t) -> t.time).thenComparingInt(t -> t.line));
        for (Tx t : txs) {
            outBy.computeIfAbsent(t.from, k -> new ArrayList<>()).add(t);
            inBy.computeIfAbsent(t.to, k -> new ArrayList<>()).add(t);
        }
    }

    static String get(String[] f, Map<String, Integer> col, String name) {
        Integer i = col.get(name);
        return (i == null || i >= f.length) ? "" : f[i].trim();
    }

    /** Minimal RFC-4180 style CSV splitter (handles quotes and doubled quotes). */
    static String[] splitCsv(String line) {
        List<String> r = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (q) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') { sb.append('"'); i++; }
                    else q = false;
                } else sb.append(c);
            } else if (c == '"') q = true;
            else if (c == ',') { r.add(sb.toString()); sb.setLength(0); }
            else sb.append(c);
        }
        r.add(sb.toString());
        return r.toArray(new String[0]);
    }

    static Instant parseTime(String s) {
        s = s.trim();
        try { return Instant.parse(s); } catch (Exception ignored) { }
        try { return OffsetDateTime.parse(s).toInstant(); } catch (Exception ignored) { }
        try { return LocalDateTime.parse(s.replace(' ', 'T')).toInstant(ZoneOffset.UTC); } catch (Exception ignored) { }
        try { return LocalDate.parse(s).atStartOfDay().toInstant(ZoneOffset.UTC); } catch (Exception ignored) { }
        throw new IllegalArgumentException("unreadable timestamp '" + s + "'");
    }

    static String sha256(byte[] data) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(data)) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    static Set<String> accounts() {
        Set<String> s = new TreeSet<>();
        for (Tx t : txs) { s.add(t.from); s.add(t.to); }
        return s;
    }

    static String money(double d) { return String.format(Locale.ROOT, "%,.2f", d); }
    static String ts(Instant i) { return TS.format(i); }
    static double sum(List<Tx> l) { return l.stream().mapToDouble(Tx::amt).sum(); }

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    static void summary() {
        out.println("== CASE DATA SUMMARY ==");
        out.println("Source file  : " + fileName);
        out.println("SHA-256      : " + fileHash + "   (record this for continuity of evidence)");
        out.println("Transactions : " + txs.size());
        out.println("Accounts     : " + accounts().size());
        if (!txs.isEmpty()) {
            out.println("Period (UTC) : " + ts(txs.get(0).time) + "  to  " + ts(txs.get(txs.size() - 1).time));
            out.println("Total value  : " + money(sum(txs)));
            Set<String> cur = txs.stream().map(t -> t.currency).filter(c -> !c.isEmpty()).collect(Collectors.toCollection(TreeSet::new));
            if (cur.size() > 1)
                out.println("WARNING      : multiple currencies " + cur + " - amounts are NOT converted; totals mix currencies.");
        }
        for (int i = 0; i < Math.min(10, warnings.size()); i++) out.println("WARNING      : " + warnings.get(i));
        if (warnings.size() > 10) out.println("WARNING      : ... and " + (warnings.size() - 10) + " more rows skipped.");
    }

    // ------------------------------------------------------------------
    // Detectors
    // ------------------------------------------------------------------
    static List<Finding> detect() {
        List<Finding> fs = new ArrayList<>();
        detectSharedIdentifiers(fs);
        detectStructuring(fs);
        detectPassThrough(fs);
        detectFan(inBy, true, fs);
        detectFan(outBy, false, fs);
        detectCycles(fs);
        return fs;
    }

    /** Accounts that SEND from the same device / IP are likely operated by the same person or group. */
    static void detectSharedIdentifiers(List<Finding> fs) {
        Map<String, Set<String>> byDev = senderMap(true), byIp = senderMap(false);
        for (Map.Entry<String, Set<String>> e : byDev.entrySet())
            if (e.getValue().size() >= sharedDeviceMin)
                for (String a : e.getValue())
                    fs.add(new Finding(a, "SHARED_DEVICE", 25,
                            "device " + e.getKey() + " also used by " + others(e.getValue(), a)));
        for (Map.Entry<String, Set<String>> e : byIp.entrySet())
            if (e.getValue().size() >= sharedIpMin)
                for (String a : e.getValue())
                    fs.add(new Finding(a, "SHARED_IP", 10,
                            "IP " + e.getKey() + " also used by " + others(e.getValue(), a)
                                    + " (weaker signal: could be shared Wi-Fi/VPN/CGNAT)"));
    }

    static Map<String, Set<String>> senderMap(boolean device) {
        Map<String, Set<String>> m = new TreeMap<>();
        for (Tx t : txs) {
            String key = device ? t.device : t.ip;
            if (!key.isEmpty()) m.computeIfAbsent(key, k -> new TreeSet<>()).add(t.from);
        }
        return m;
    }

    static String others(Set<String> all, String me) {
        return all.stream().filter(x -> !x.equals(me)).collect(Collectors.toList()).toString();
    }

    /** Several payments just under a reporting threshold in a short window. */
    static void detectStructuring(List<Finding> fs) {
        double lo = structThreshold * 0.8;
        for (Map.Entry<String, List<Tx>> e : outBy.entrySet()) {
            List<Tx> band = e.getValue().stream()
                    .filter(t -> t.amt() >= lo && t.amt() < structThreshold).collect(Collectors.toList());
            int best = 0, bestStart = 0, j = 0;
            for (int i = 0; i < band.size(); i++) {
                while (Duration.between(band.get(j).time, band.get(i).time).toHours() > structWindowHours) j++;
                if (i - j + 1 > best) { best = i - j + 1; bestStart = j; }
            }
            if (best >= structMin) {
                double total = sum(band.subList(bestStart, bestStart + best));
                fs.add(new Finding(e.getKey(), "STRUCTURING", 25,
                        best + " payments of " + money(lo) + "-" + money(structThreshold) + " within "
                                + structWindowHours + "h (total " + money(total) + ", from "
                                + ts(band.get(bestStart).time) + ")"));
            }
        }
    }

    /** Money arrives and leaves almost immediately: typical of a money-mule account. FIFO matching. */
    static void detectPassThrough(List<Finding> fs) {
        for (String acct : accounts()) {
            List<Tx> ins = inBy.getOrDefault(acct, List.of()), outs = outBy.getOrDefault(acct, List.of());
            if (ins.isEmpty() || outs.isEmpty()) continue;
            double totIn = sum(ins);
            if (totIn < passMinTotal) continue;
            ArrayDeque<double[]> q = new ArrayDeque<>();   // {remaining, arrival epoch seconds}
            int a = 0;
            double matched = 0, weighted = 0;
            for (Tx o : outs) {
                while (a < ins.size() && !ins.get(a).time.isAfter(o.time)) {
                    q.add(new double[]{ins.get(a).amt(), ins.get(a).time.getEpochSecond()});
                    a++;
                }
                double need = o.amt();
                while (need > 0.005 && !q.isEmpty()) {
                    double[] h = q.peek();
                    double take = Math.min(h[0], need);
                    h[0] -= take; need -= take; matched += take;
                    weighted += take * (o.time.getEpochSecond() - h[1]);
                    if (h[0] <= 0.005) q.poll();
                }
            }
            if (matched <= 0) continue;
            double avgHours = weighted / matched / 3600.0, ratio = matched / totIn;
            if (ratio >= passRatio && avgHours <= passDwellHours)
                fs.add(new Finding(acct, "PASS_THROUGH", 30,
                        String.format(Locale.ROOT, "%.0f%% of %s received was forwarded on, held on average %.1f hours",
                                ratio * 100, money(totIn), avgHours)));
        }
    }

    /** Many different counterparties paying in (collection account) or being paid out (dispersal) in a short window. */
    static void detectFan(Map<String, List<Tx>> by, boolean incoming, List<Finding> fs) {
        for (Map.Entry<String, List<Tx>> e : by.entrySet()) {
            List<Tx> l = e.getValue();
            Map<String, Integer> cnt = new HashMap<>();
            int j = 0, bestD = 0;
            double sum = 0, bestSum = 0;
            for (int i = 0; i < l.size(); i++) {
                Tx t = l.get(i);
                cnt.merge(incoming ? t.from : t.to, 1, Integer::sum);
                sum += t.amt();
                while (Duration.between(l.get(j).time, t.time).toHours() > fanWindowDays * 24L) {
                    Tx r = l.get(j);
                    String c = incoming ? r.from : r.to;
                    if (cnt.merge(c, -1, Integer::sum) == 0) cnt.remove(c);
                    sum -= r.amt();
                    j++;
                }
                if (cnt.size() > bestD) { bestD = cnt.size(); bestSum = sum; }
            }
            if (bestD >= fanMin)
                fs.add(new Finding(e.getKey(), incoming ? "FAN_IN" : "FAN_OUT", 20,
                        bestD + " different " + (incoming ? "senders paid this account" : "recipients were paid")
                                + " within " + fanWindowDays + " days (" + money(bestSum) + ")"));
        }
    }

    /** Money going round in circles (A->B->C->A) is a classic layering pattern. */
    static void detectCycles(List<Finding> fs) {
        Map<String, Set<String>> adj = new TreeMap<>();
        for (Tx t : txs) if (!t.from.equals(t.to)) adj.computeIfAbsent(t.from, k -> new TreeSet<>()).add(t.to);
        List<List<String>> cycles = new ArrayList<>();
        for (String s : adj.keySet()) dfs(s, s, new ArrayList<>(List.of(s)), adj, cycles);
        for (List<String> c : cycles) {
            String path = String.join(" -> ", c) + " -> " + c.get(0);
            for (String a : c) fs.add(new Finding(a, "CIRCULAR_FLOW", 15, "part of loop " + path));
        }
    }

    static void dfs(String start, String cur, List<String> path, Map<String, Set<String>> adj, List<List<String>> out) {
        if (out.size() >= 200) return;
        for (String nx : adj.getOrDefault(cur, Collections.emptySet())) {
            if (nx.equals(start)) {
                if (path.size() >= 3) out.add(new ArrayList<>(path));
            } else if (nx.compareTo(start) > 0 && !path.contains(nx) && path.size() < cycleMaxLen) {
                path.add(nx);
                dfs(start, nx, path, adj, out);
                path.remove(path.size() - 1);
            }
        }
    }

    // ------------------------------------------------------------------
    // analyze
    // ------------------------------------------------------------------
    static void analyze() {
        List<Finding> fs = detect();
        out.println("== SUSPICION RANKING ==");
        if (fs.isEmpty()) { out.println("No patterns matched the current thresholds (see 'set')."); return; }
        Map<String, List<Finding>> by = new HashMap<>();
        for (Finding f : fs) by.computeIfAbsent(f.account, k -> new ArrayList<>()).add(f);
        List<Map.Entry<String, List<Finding>>> ranked = new ArrayList<>(by.entrySet());
        ranked.sort((x, y) -> {
            int c = Integer.compare(score(y.getValue()), score(x.getValue()));
            return c != 0 ? c : x.getKey().compareTo(y.getKey());
        });
        int shown = 0;
        for (Map.Entry<String, List<Finding>> e : ranked) {
            if (shown++ >= 25) { out.println("\n... " + (ranked.size() - 25) + " lower-scoring accounts not shown."); break; }
            int sc = score(e.getValue());
            out.println();
            out.println(String.format("%-22s score %3d  [%s]  in %s / out %s", e.getKey(), sc,
                    sc >= 60 ? "HIGH" : sc >= 30 ? "MEDIUM" : "LOW",
                    money(sum(inBy.getOrDefault(e.getKey(), List.of()))),
                    money(sum(outBy.getOrDefault(e.getKey(), List.of())))));
            for (Finding f : e.getValue()) out.println("    - " + f.type + ": " + f.detail);
        }
        out.println("\nNote: scores are a triage aid only. Legitimate activity (businesses, charities, shared"
                + " households) can match these patterns. Verify with source records.");
    }

    static int score(List<Finding> l) { return l.stream().mapToInt(f -> f.weight).sum(); }

    // ------------------------------------------------------------------
    // links: clusters of accounts connected by shared device / IP
    // ------------------------------------------------------------------
    static void links() {
        Map<String, Set<String>> byDev = senderMap(true), byIp = senderMap(false);
        Map<String, String> parent = new HashMap<>();
        for (Map.Entry<String, Set<String>> e : byDev.entrySet()) if (e.getValue().size() >= sharedDeviceMin) union(parent, e.getValue());
        for (Map.Entry<String, Set<String>> e : byIp.entrySet()) if (e.getValue().size() >= sharedIpMin) union(parent, e.getValue());

        Map<String, Set<String>> clusters = new TreeMap<>();
        for (String a : new ArrayList<>(parent.keySet())) clusters.computeIfAbsent(find(parent, a), k -> new TreeSet<>()).add(a);
        out.println("== LINKED ACCOUNT CLUSTERS (shared device / IP) ==");
        if (clusters.isEmpty()) { out.println("None found."); return; }
        int n = 1;
        for (Set<String> members : clusters.values()) {
            out.println("\nCluster " + n++ + ": " + members);
            for (Map.Entry<String, Set<String>> e : byDev.entrySet())
                if (e.getValue().size() >= sharedDeviceMin && members.containsAll(e.getValue()))
                    out.println("    device " + e.getKey() + " used by " + e.getValue());
            for (Map.Entry<String, Set<String>> e : byIp.entrySet())
                if (e.getValue().size() >= sharedIpMin && members.containsAll(e.getValue()))
                    out.println("    IP     " + e.getKey() + " used by " + e.getValue());
            double in = 0, o = 0;
            for (String m : members) { in += sum(inBy.getOrDefault(m, List.of())); o += sum(outBy.getOrDefault(m, List.of())); }
            out.println("    combined received " + money(in) + ", combined sent " + money(o));
        }
    }

    static void union(Map<String, String> parent, Set<String> group) {
        String first = null;
        for (String a : group) {
            parent.putIfAbsent(a, a);
            if (first == null) first = a; else parent.put(find(parent, a), find(parent, first));
        }
    }

    static String find(Map<String, String> p, String x) {
        while (!p.get(x).equals(x)) { p.put(x, p.get(p.get(x))); x = p.get(x); }
        return x;
    }

    // ------------------------------------------------------------------
    // trace: follow tainted money forward in time
    // ------------------------------------------------------------------
    static void trace(List<Tx> seeds, String label) {
        if (seeds.isEmpty()) { out.println("No starting transactions found."); return; }
        Set<Tx> seedSet = Collections.newSetFromMap(new IdentityHashMap<>());
        seedSet.addAll(seeds);
        Instant start = seeds.stream().map(t -> t.time).min(Comparator.naturalOrder()).get();
        double seeded = sum(seeds);

        out.println("== MONEY TRAIL ==");
        out.println("Starting from: " + label);
        out.println("Seed amount  : " + money(seeded) + " across " + seeds.size() + " payment(s)\n");

        Map<String, Double> held = new HashMap<>();
        for (Tx t : txs) {
            if (t.time.isBefore(start)) continue;
            double moved;
            if (seedSet.contains(t)) moved = t.amt();
            else {
                moved = Math.min(held.getOrDefault(t.from, 0.0), t.amt());
                if (moved < 0.005) continue;
                held.merge(t.from, -moved, Double::sum);
            }
            held.merge(t.to, moved, Double::sum);
            out.println(String.format("%s  %-8s %-18s -> %-18s %12s of %12s  ip=%s dev=%s%s",
                    ts(t.time), t.id, t.from, t.to, money(moved), money(t.amt()),
                    t.ip.isEmpty() ? "-" : t.ip, t.device.isEmpty() ? "-" : t.device,
                    t.memo.isEmpty() ? "" : "  \"" + t.memo + "\""));
        }

        out.println("\n== WHERE THE MONEY IS NOW (per this data) ==");
        List<Map.Entry<String, Double>> rest = held.entrySet().stream()
                .filter(e -> e.getValue() >= 0.01 && !accountIsSeedSource(e.getKey(), seeds))
                .sorted((x, y) -> Double.compare(y.getValue(), x.getValue())).collect(Collectors.toList());
        if (rest.isEmpty()) out.println("Nothing traceable remains.");
        for (Map.Entry<String, Double> e : rest) {
            boolean sink = !outBy.containsKey(e.getKey());
            out.println(String.format("%-22s %12s  (%4.1f%%)  %s", e.getKey(), money(e.getValue()),
                    e.getValue() / seeded * 100,
                    sink ? "<- no onward payments in data: likely cash-out/exit point. Priority for freezing/production orders."
                         : "<- still held, or moved by a route not in this data"));
        }
        out.println("\nMethod: chronological tracing; each onward payment is assumed to carry traced funds up to the"
                + " amount of traced money the sender held at that moment. This is an investigative aid - the legal"
                + " rules for tracing mixed funds differ and should be confirmed with the prosecutor.");
    }

    static boolean accountIsSeedSource(String acct, List<Tx> seeds) {
        return seeds.stream().anyMatch(t -> t.from.equals(acct));
    }

    // ------------------------------------------------------------------
    // timeline & account profile
    // ------------------------------------------------------------------
    static void timeline(String acct) {
        out.println("== TIMELINE: " + acct + " ==");
        double net = 0;
        for (Tx t : txs) {
            boolean i = t.to.equals(acct), o = t.from.equals(acct);
            if (!i && !o) continue;
            net += i ? t.amt() : -t.amt();
            out.println(String.format("%s  %-8s %-3s %-18s %12s  net %13s  ip=%s dev=%s",
                    ts(t.time), t.id, i ? "IN" : "OUT", i ? t.from : t.to, money(t.amt()), money(net),
                    t.ip.isEmpty() ? "-" : t.ip, t.device.isEmpty() ? "-" : t.device));
        }
        out.println("(net = total in minus total out within this data only, not the real balance)");
    }

    static void account(String acct) {
        List<Tx> in = inBy.getOrDefault(acct, List.of()), o = outBy.getOrDefault(acct, List.of());
        out.println("== ACCOUNT: " + acct + " ==");
        out.println("Received : " + money(sum(in)) + " in " + in.size() + " payment(s) from "
                + in.stream().map(t -> t.from).distinct().count() + " account(s)");
        out.println("Sent     : " + money(sum(o)) + " in " + o.size() + " payment(s) to "
                + o.stream().map(t -> t.to).distinct().count() + " account(s)");
        List<Tx> all = new ArrayList<>(in); all.addAll(o);
        all.sort(Comparator.comparing((Tx t) -> t.time));
        out.println("Active   : " + ts(all.get(0).time) + "  to  " + ts(all.get(all.size() - 1).time));
        out.println("IPs used (as sender)    : " + o.stream().map(t -> t.ip).filter(s -> !s.isEmpty()).collect(Collectors.toCollection(TreeSet::new)));
        out.println("Devices used (as sender): " + o.stream().map(t -> t.device).filter(s -> !s.isEmpty()).collect(Collectors.toCollection(TreeSet::new)));
        out.println("Top payers : " + top(in, true));
        out.println("Top payees : " + top(o, false));
        List<Finding> fs = detect().stream().filter(f -> f.account.equals(acct)).collect(Collectors.toList());
        out.println("Findings   : " + (fs.isEmpty() ? "none" : ""));
        for (Finding f : fs) out.println("    - " + f.type + ": " + f.detail);
    }

    static String top(List<Tx> l, boolean incoming) {
        Map<String, Double> m = new HashMap<>();
        for (Tx t : l) m.merge(incoming ? t.from : t.to, t.amt(), Double::sum);
        return m.entrySet().stream().sorted((a, b) -> Double.compare(b.getValue(), a.getValue())).limit(5)
                .map(e -> e.getKey() + " (" + money(e.getValue()) + ")").collect(Collectors.joining(", "));
    }

    // ------------------------------------------------------------------
    // report
    // ------------------------------------------------------------------
    static void report(Path file, String victim) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bos, true, "UTF-8");
        PrintStream old = out;
        out = ps;
        try {
            out.println("SHERLOCK CASE REPORT");
            out.println("Generated : " + ts(Instant.now()) + " UTC");
            out.println("Settings  : structuring threshold " + money(structThreshold) + ", pass-through >= "
                    + (int) (passRatio * 100) + "% within " + passDwellHours + "h, fan >= " + fanMin
                    + " in " + fanWindowDays + "d, shared device >= " + sharedDeviceMin + ", shared IP >= " + sharedIpMin + "\n");
            summary();
            out.println();
            analyze();
            out.println();
            links();
            if (victim != null) {
                requireAccount(victim);
                out.println();
                trace(outBy.getOrDefault(victim, List.of()), "all payments out of " + victim);
            }
            out.println("\nDISCLAIMER: automated analysis for investigative guidance only. Not evidence in itself.");
        } finally {
            out = old;
        }
        Files.write(file, bos.toByteArray());
        out.println("Report written to " + file.toAbsolutePath());
    }

    // ------------------------------------------------------------------
    // Demo data: an investment scam with mule layering and a cash-out
    // ------------------------------------------------------------------
    static void writeDemo(Path p) throws IOException {
        Instant base = Instant.parse("2026-03-02T09:00:00Z");
        List<String> r = new ArrayList<>();
        r.add("id,timestamp,from,to,amount,currency,ip,device,memo");

        // The victim is groomed into four "investment" deposits
        add(r, base, 0,    "ACC-VICTIM-01", "ACC-M01", "12000.00", "198.51.100.7", "VICT-LAPTOP", "Investment platform deposit");
        add(r, base, 400,  "ACC-VICTIM-01", "ACC-M01", "7500.00",  "198.51.100.7", "VICT-LAPTOP", "Top-up to unlock withdrawal");
        add(r, base, 900,  "ACC-VICTIM-01", "ACC-M01", "11000.00", "198.51.100.7", "VICT-LAPTOP", "Tax fee");
        add(r, base, 1300, "ACC-VICTIM-01", "ACC-M01", "7500.00",  "198.51.100.7", "VICT-LAPTOP", "Release fee");
        // Other victims of the same scam pay the same account
        String[] vs = {"ACC-VICTIM-02", "ACC-VICTIM-03", "ACC-VICTIM-04", "ACC-VICTIM-05", "ACC-VICTIM-06"};
        int[] vm = {100, 300, 700, 1100, 1500};
        for (int i = 0; i < vs.length; i++)
            add(r, base, vm[i], vs[i], "ACC-M01", "2000.00", "198.51.100." + (21 + i), "V0" + (i + 2) + "-PHONE", "Investment");

        // M01 fans the money out in just-under-10k chunks
        add(r, base, 1600, "ACC-M01", "ACC-M02", "9500.00", "203.0.113.50", "DEV-77", "");
        add(r, base, 1620, "ACC-M01", "ACC-M03", "9600.00", "203.0.113.50", "DEV-77", "");
        add(r, base, 1640, "ACC-M01", "ACC-M04", "9700.00", "203.0.113.50", "DEV-77", "");
        add(r, base, 1660, "ACC-M01", "ACC-M05", "9500.00", "203.0.113.50", "DEV-77", "");
        add(r, base, 1680, "ACC-M01", "ACC-M09", "9400.00", "203.0.113.50", "DEV-77", "");

        // Second layer
        add(r, base, 1700, "ACC-M02", "EXCHANGE-A",  "9400.00", "203.0.113.50", "DEV-77", "");
        add(r, base, 1750, "ACC-M04", "EXCHANGE-A",  "9600.00", "192.0.2.31",   "DEV-31", "");
        add(r, base, 1900, "ACC-M09", "CRYPTO-WLT-9", "9300.00", "203.0.113.50", "DEV-77", "");
        // Loop used to muddy the trail (M03 -> M06 -> M07 -> M03), then exit
        add(r, base, 1800, "ACC-M03", "ACC-M06", "9500.00", "192.0.2.10", "DEV-12", "");
        add(r, base, 1900, "ACC-M06", "ACC-M07", "9400.00", "192.0.2.11", "DEV-12", "");
        add(r, base, 2000, "ACC-M07", "ACC-M03", "9300.00", "192.0.2.12", "DEV-12", "");
        add(r, base, 2100, "ACC-M03", "EXCHANGE-B",  "9200.00", "192.0.2.10", "DEV-12", "");
        // Chain via M08
        add(r, base, 1850, "ACC-M05", "ACC-M08", "9400.00", "192.0.2.32", "DEV-32", "");
        add(r, base, 2200, "ACC-M08", "EXCHANGE-C",  "9300.00", "192.0.2.33", "DEV-33", "");

        // Legitimate background noise
        Random rnd = new Random(42);
        for (int i = 0; i < 45; i++) {
            int a = 1 + rnd.nextInt(20), b = 1 + rnd.nextInt(20);
            if (a == b) b = (b % 20) + 1;
            add(r, base, -4000 + rnd.nextInt(12000), String.format("ACC-C%02d", a), String.format("ACC-C%02d", b),
                    String.format(Locale.ROOT, "%.2f", 15 + rnd.nextDouble() * 885),
                    "192.0.2." + (100 + a), "C" + a + "-DEV", "");
        }
        Files.write(p, r, StandardCharsets.UTF_8);
    }

    static void add(List<String> rows, Instant base, long minutes, String from, String to,
                    String amount, String ip, String dev, String memo) {
        rows.add(String.format("TX%04d,%s,%s,%s,%s,GBP,%s,%s,%s", rows.size(),
                base.plus(Duration.ofMinutes(minutes)), from, to, amount, ip, dev, memo));
    }
}
