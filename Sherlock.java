import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.*;
import java.util.function.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * SHERLOCK 2 - a transaction-analysis assistant for investigating online financial crime
 * (investment scams, romance scams, authorised push payment fraud, account takeover, money mules).
 *
 * Single file, no external dependencies. Requires Java 11 or newer.
 *
 *   Run:       java Sherlock.java [options] <file.csv> [file2.csv ...]            (interactive shell)
 *              java Sherlock.java [options] <file.csv> ... <command> [args]       (one-shot)
 *   Demo:      java Sherlock.java demo demo.csv     then    java Sherlock.java demo.csv
 *   Self-test: java Sherlock.java selftest
 *   Mapping:   java Sherlock.java maptemplate bank.properties   (column-mapping profile for bank exports)
 *
 * Options: --tz <zone>  --map <mapping.properties> (applies to the files after it)  --decimal-comma
 *          --base <currency>  --rates <rates.csv>  --watchlist <watchlist.csv>  --config <settings.properties>
 *          --analyst <name>  --no-dedupe
 *
 * Standard CSV columns (header row required, order irrelevant, extra columns ignored):
 *   timestamp, from, to, amount             <- required
 *   id, currency, ip, device, memo          <- optional but very useful ("ip"/"device" = the SENDER's session)
 *
 * IMPORTANT: Sherlock produces investigative LEADS, not proof. Every finding must be verified
 * against original bank/provider records and handled under your force's evidence procedures.
 */
public class Sherlock {

    static final String VERSION = "2.0.0";
    static final String CLEAN = "";   // label for money that is not being traced
    static final List<String> MODES = List.of("tainted-first", "clean-first", "fifo", "prorata");
    static final Map<String, String> MODE_TEXT = Map.of(
            "tainted-first", "each payment out of an account carries traced money first, then untraced money. "
                    + "Follows the most money outward; can overstate the traced share downstream when a mule also holds other funds.",
            "clean-first", "untraced money leaves first and traced money stays in each account for as long as possible. "
                    + "The most conservative view of how far the money travelled.",
            "fifo", "money leaves each account in the order it arrived (first in, first out), as in the rule in Clayton's Case.",
            "prorata", "every payment carries traced and untraced money in proportion to the account's balance at that moment "
                    + "(a rateable, pari passu split).");

    // =====================================================================
    // Entry point
    // =====================================================================
    public static void main(String[] args) throws Exception {
        if (args.length == 0) { new Case(System.out).usage(); return; }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "demo": {
                Path p = Paths.get(args.length > 1 ? args[1] : "demo.csv");
                writeDemo(p);
                System.out.println("Demo case written to " + p
                        + "\nTry:   java Sherlock.java " + p
                        + "\nThen:  analyze  |  trace ACC-VICTIM-01  |  compare ACC-VICTIM-01  |  report case.html ACC-VICTIM-01");
                return;
            }
            case "selftest":
                System.exit(SelfTest.run(System.out) ? 0 : 1);
                return;
            case "maptemplate":
                if (args.length > 1) {
                    Files.write(Paths.get(args[1]), MAP_TEMPLATE.getBytes(StandardCharsets.UTF_8));
                    System.out.println("Mapping template written to " + args[1]);
                } else System.out.print(MAP_TEMPLATE);
                return;
            default:
        }
        Case c = new Case(System.out);
        List<String> command;
        try {
            command = c.applyCommandLine(args);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
            return;
        }
        if (command.isEmpty()) c.shell();
        else {
            try { c.exec(command); }
            catch (Exception e) { System.err.println("Error: " + e.getMessage()); System.exit(1); }
        }
    }

    // =====================================================================
    // Model
    // =====================================================================
    static final class Tx {
        String id, ip, device, memo, mergedFrom = "";
        final String from, to, currency, src;
        final int line;
        final Instant time;
        final BigDecimal amount;     // as written in the source, in its own currency
        long value;                  // minor units (pence) in the base currency
        boolean converted = true, laterRate = false;
        BigDecimal rate;
        LocalDate rateDate;

        Tx(String src, int line, String id, Instant time, String from, String to, BigDecimal amount,
           String currency, String ip, String device, String memo) {
            this.src = src; this.line = line; this.id = id; this.time = time; this.from = from; this.to = to;
            this.amount = amount; this.currency = currency; this.ip = ip; this.device = device; this.memo = memo;
        }

        String ref() { return src + ":" + line; }
        String cur(String base) { return currency.isEmpty() ? base : currency; }
    }

    static final class Finding {
        final String account, type, detail;
        final int weight;
        final boolean safeguarding;    // true = the account looks like a VICTIM or a compromised account
        final List<String> txIds;

        Finding(String account, String type, int weight, boolean safeguarding, String detail, List<String> txIds) {
            this.account = account; this.type = type; this.weight = weight; this.safeguarding = safeguarding;
            this.detail = detail; this.txIds = txIds;
        }
    }

    static final class Ranked {
        final String account;
        final List<Finding> findings = new ArrayList<>();
        int score;
        long in, out;
        Ranked(String account) { this.account = account; }
    }

    static final class Source {
        String name, path, hash, mapping, encoding = "UTF-8", zone = "UTC";
        boolean explicitZone;
        int rows, loaded, skipped, merged, zoned, zoneless;
    }

    static final class Cluster {
        final Set<String> members = new TreeSet<>();
        final List<String> reasons = new ArrayList<>();
        long in, out;
    }

    static final class Edge {
        final String from, to;
        long total;
        int count;
        Instant first, last;
        final List<String> ids = new ArrayList<>();
        Edge(String from, String to) { this.from = from; this.to = to; }
    }

    static final class Mapping {
        String name = "standard";
        boolean standard = true;
        final Map<String, String> cols = new HashMap<>();
        String owner, tsFormat, dateFormat, timeFormat, defaultCurrency = "";
        char delimiter = ',';
        Boolean decimalComma;
        ZoneId tz;
        int skipLines;
        Set<String> dirOut = new HashSet<>(List.of("DEBIT", "DR", "OUT", "D", "PAYMENT", "WITHDRAWAL"));
        Set<String> dirIn = new HashSet<>(List.of("CREDIT", "CR", "IN", "C", "RECEIPT", "DEPOSIT"));
    }

    static final List<String> FIELDS = List.of("id", "timestamp", "date", "time", "from", "to", "amount", "debit",
            "credit", "counterparty", "direction", "currency", "ip", "device", "memo");
    static final Set<String> MAP_SETTINGS = Set.of("name", "owner", "timestamp.format", "date.format", "time.format",
            "delimiter", "decimalcomma", "tz", "skiplines", "currency.default", "direction.out", "direction.in");

    static final class Settings {
        List<Long> thresholds = new ArrayList<>(List.of(1_000_000L));
        double structBand = 0.80;
        int structMin = 3, structWindowHours = 72;
        double passRatio = 0.90;
        long passMin = 100_000;
        int dwellHours = 48;
        int fanMin = 5, fanWindowDays = 7;
        int deviceMin = 2, ipMin = 3;
        int cycleMaxLen = 4, cycleWindowHours = 168;
        long cycleMin = 100_000;
        int victimMin = 3, victimWindowDays = 30;
        List<String> keywords = new ArrayList<>(List.of("invest", "profit", "trading", "platform", "crypto", "bitcoin",
                "btc", "usdt", "wallet", "fee", "tax", "unlock", "release", "withdraw", "clearance", "verif",
                "customs", "upgrade", "commission", "insurance", "deposit", "top-up", "topup", "refund", "loan",
                "hospital", "emergency", "visa", "flight", "safe account"));
        int atoHistory = 3, atoWindowHours = 24;
        double atoFactor = 3.0;
        int dormantDays = 60, burstDays = 7;
        long roundUnit = 50_000;
        double roundRatio = 0.8;
        int roundMin = 4;
        int repeatMin = 4, repeatWindowDays = 30;
        long repeatMinAmount = 10_000;
        String traceMode = "tainted-first";
        boolean dedupe = true;
        int dedupeWindowHours = 48;
        String base = "GBP";
        ZoneId tz = ZoneId.of("UTC");
        boolean tzExplicit = false, decimalComma = false;
        String analyst = "";
        final Set<String> disabled = new TreeSet<>();
    }

    static final class Param {
        final String name, help;
        final Supplier<String> get;
        final Consumer<String> set;
        Param(String name, String help, Supplier<String> get, Consumer<String> set) {
            this.name = name; this.help = help; this.get = get; this.set = set;
        }
    }

    interface DetectorFn { void run(List<Finding> fs, List<String> notes); }

    static final class Detector {
        final String name, types, description;
        final DetectorFn fn;
        Detector(String name, String types, String description, DetectorFn fn) {
            this.name = name; this.types = types; this.description = description; this.fn = fn;
        }
    }

    interface Action { void run() throws Exception; }

    // ---------------------------------------------------------------------
    // Tracing model: every account is a pool of labelled money
    // ---------------------------------------------------------------------
    static final class Lot {
        final String label;
        long amt;
        Lot(String label, long amt) { this.label = label; this.amt = amt; }
    }

    static final class Pool {
        final String mode;
        final ArrayDeque<Lot> lots = new ArrayDeque<>();      // fifo
        final TreeMap<String, Long> bal = new TreeMap<>();     // other modes

        Pool(String mode) { this.mode = mode; }

        void deposit(Map<String, Long> parts) {
            for (Map.Entry<String, Long> e : parts.entrySet()) {
                if (e.getValue() <= 0) continue;
                if (mode.equals("fifo")) lots.addLast(new Lot(e.getKey(), e.getValue()));
                else bal.merge(e.getKey(), e.getValue(), Long::sum);
            }
        }

        /** Takes up to amt out of the pool; returns label -> amount taken (may total less than amt). */
        TreeMap<String, Long> withdraw(long amt) {
            TreeMap<String, Long> r = new TreeMap<>();
            if (amt <= 0) return r;
            if (mode.equals("fifo")) {
                while (amt > 0 && !lots.isEmpty()) {
                    Lot h = lots.peekFirst();
                    long take = Math.min(h.amt, amt);
                    h.amt -= take; amt -= take;
                    r.merge(h.label, take, Long::sum);
                    if (h.amt == 0) lots.pollFirst();
                }
                return r;
            }
            if (mode.equals("prorata")) {
                r = split(bal, amt);
                debit(bal, r);
                return r;
            }
            TreeMap<String, Long> tainted = new TreeMap<>(bal);
            tainted.remove(CLEAN);
            long clean = bal.getOrDefault(CLEAN, 0L), taint = total(tainted);
            if (mode.equals("tainted-first")) {
                r = split(tainted, Math.min(amt, taint));
                long c = Math.min(amt - total(r), clean);
                if (c > 0) r.put(CLEAN, c);
            } else {   // clean-first
                long c = Math.min(amt, clean);
                if (c > 0) r.put(CLEAN, c);
                r.putAll(split(tainted, Math.min(amt - c, taint)));
            }
            debit(bal, r);
            return r;
        }

        TreeMap<String, Long> holdings() {
            TreeMap<String, Long> h = new TreeMap<>();
            if (mode.equals("fifo")) { for (Lot l : lots) if (l.amt > 0) h.merge(l.label, l.amt, Long::sum); }
            else for (Map.Entry<String, Long> e : bal.entrySet()) if (e.getValue() > 0) h.put(e.getKey(), e.getValue());
            return h;
        }
    }

    static final class Step {
        final Tx tx;
        final TreeMap<String, Long> parts;   // traced labels only
        Step(Tx tx, TreeMap<String, Long> parts) { this.tx = tx; this.parts = parts; }
    }

    static final class Trace {
        String mode, label = "";
        final Map<String, Long> seeded = new TreeMap<>();
        final Map<String, Integer> seedCount = new TreeMap<>();
        final List<Step> steps = new ArrayList<>();
        final Map<String, Pool> pools = new HashMap<>();
        final Map<String, Long> intoTarget = new TreeMap<>();
        long targetReceived;
        int targetPayments;

        long seededTotal() { return total(seeded); }
        int seedPayments() { return seedCount.values().stream().mapToInt(Integer::intValue).sum(); }

        Map<String, TreeMap<String, Long>> held() {
            Map<String, TreeMap<String, Long>> m = new TreeMap<>();
            for (Map.Entry<String, Pool> e : pools.entrySet()) {
                TreeMap<String, Long> h = e.getValue().holdings();
                h.remove(CLEAN);
                if (!h.isEmpty()) m.put(e.getKey(), h);
            }
            return m;
        }
    }

    /** Splits amt across the labels in proportion to their balances (largest remainder, never exceeding a balance). */
    static TreeMap<String, Long> split(Map<String, Long> bal, long amt) {
        TreeMap<String, Long> r = new TreeMap<>();
        long tot = total(bal);
        if (amt <= 0 || tot <= 0) return r;
        if (amt >= tot) {
            for (Map.Entry<String, Long> e : bal.entrySet()) if (e.getValue() > 0) r.put(e.getKey(), e.getValue());
            return r;
        }
        BigInteger a = BigInteger.valueOf(amt), t = BigInteger.valueOf(tot);
        List<String> keys = new ArrayList<>();
        Map<String, BigInteger> rem = new HashMap<>();
        long given = 0;
        for (Map.Entry<String, Long> e : bal.entrySet()) {
            if (e.getValue() <= 0) continue;
            BigInteger[] qr = a.multiply(BigInteger.valueOf(e.getValue())).divideAndRemainder(t);
            long q = qr[0].longValue();
            r.put(e.getKey(), q);
            given += q;
            keys.add(e.getKey());
            rem.put(e.getKey(), qr[1]);
        }
        keys.sort((x, y) -> {
            int c = rem.get(y).compareTo(rem.get(x));
            return c != 0 ? c : x.compareTo(y);
        });
        for (int i = 0; given < amt && !keys.isEmpty(); i = (i + 1) % keys.size()) {
            String k = keys.get(i);
            if (r.get(k) < bal.get(k)) { r.merge(k, 1L, Long::sum); given++; }
        }
        r.values().removeIf(v -> v == 0);
        return r;
    }

    static long total(Map<String, Long> m) {
        long t = 0;
        for (long v : m.values()) t += v;
        return t;
    }

    static void debit(Map<String, Long> bal, Map<String, Long> taken) {
        for (Map.Entry<String, Long> e : taken.entrySet()) {
            long left = bal.getOrDefault(e.getKey(), 0L) - e.getValue();
            if (left == 0) bal.remove(e.getKey()); else bal.put(e.getKey(), left);
        }
    }

    // =====================================================================
    // Static helpers
    // =====================================================================
    static final Pattern AMT_DOT = Pattern.compile("-?\\d{1,3}(,\\d{3})+(\\.\\d+)?|-?\\d+(\\.\\d+)?");
    static final Pattern AMT_COMMA = Pattern.compile("-?\\d{1,3}(\\.\\d{3})+(,\\d+)?|-?\\d+(,\\d+)?");

    /**
     * Parses an amount strictly. Anything ambiguous is rejected instead of being silently misread:
     * "1.234,56" needs --decimal-comma, "(500.00)" (accounting negative) is refused.
     */
    static BigDecimal parseAmount(String raw, boolean decimalComma) {
        String t = raw.trim();
        if (t.isEmpty()) throw new IllegalArgumentException("blank amount");
        if (t.startsWith("(") && t.endsWith(")"))
            throw new IllegalArgumentException("bracketed amount '" + raw + "' (accounting-style negative): the direction is"
                    + " ambiguous - fix the source or use debit/credit columns in a mapping file");
        t = t.replaceAll("^[A-Za-z]{3}\\s+|\\s+[A-Za-z]{3}$", "");
        t = t.replaceAll("[£$€\\s ']", "");
        if (t.startsWith("+")) t = t.substring(1);
        if (!(decimalComma ? AMT_COMMA : AMT_DOT).matcher(t).matches()) {
            String hint = !decimalComma && t.matches("-?[\\d.]*,\\d{1,2}") ? " - looks like a decimal comma: use --decimal-comma"
                    : decimalComma && t.matches("-?\\d+\\.\\d{1,2}") ? " - decimal-comma mode is on but this uses a decimal point" : "";
            throw new IllegalArgumentException("ambiguous or malformed amount '" + raw + "'" + hint);
        }
        t = decimalComma ? t.replace(".", "").replace(',', '.') : t.replace(",", "");
        return new BigDecimal(t);
    }

    static long minor(BigDecimal a) { return a.movePointRight(2).setScale(0, RoundingMode.HALF_EVEN).longValueExact(); }

    static String money(long v) {
        long a = Math.abs(v);
        return (v < 0 ? "-" : "") + String.format(Locale.ROOT, "%,d.%02d", a / 100, a % 100);
    }

    static String plain(long v) {
        long a = Math.abs(v);
        return (v < 0 ? "-" : "") + String.format(Locale.ROOT, "%d.%02d", a / 100, a % 100);
    }

    static long sum(Collection<Tx> l) {
        long t = 0;
        for (Tx x : l) t += x.value;
        return t;
    }

    static long secs(Instant a, Instant b) { return b.getEpochSecond() - a.getEpochSecond(); }

    static String dur(long s) {
        s = Math.abs(s);
        long d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60;
        return d > 0 ? d + "d " + h + "h" : h + "h " + String.format(Locale.ROOT, "%02dm", m);
    }

    static double pct(long part, long whole) { return whole == 0 ? 0 : part * 100.0 / whole; }

    static long median(List<Long> v) {
        if (v.isEmpty()) return 0;
        List<Long> s = new ArrayList<>(v);
        Collections.sort(s);
        int n = s.size();
        return n % 2 == 1 ? s.get(n / 2) : (s.get(n / 2 - 1) + s.get(n / 2)) / 2;
    }

    static List<String> ids(Collection<Tx> l) { return l.stream().map(t -> t.id).collect(Collectors.toList()); }

    static String dash(String s) { return s == null || s.isEmpty() ? "-" : s; }

    static String oneLine(String s) { return s.replace("\r", " ").replace("\n", " / "); }

    static String clip(String s, int n) { return s.length() <= n ? s : s.substring(0, n - 1) + "~"; }

    static String others(Collection<String> all, String me) {
        return all.stream().filter(x -> !x.equals(me)).collect(Collectors.toList()).toString();
    }

    static String sha256(byte[] data) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(data)) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static String csv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r"))
            return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }

    static String h(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<': b.append("&lt;"); break;
                case '>': b.append("&gt;"); break;
                case '&': b.append("&amp;"); break;
                case '"': b.append("&quot;"); break;
                case '\'': b.append("&#39;"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }

    static String num(double d) {
        String s = String.format(Locale.ROOT, "%.4f", d);
        s = s.replaceAll("0+$", "");
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }

    static int lev(String a, String b) {
        int[] p = new int[b.length() + 1], c = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) p[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            c[0] = i;
            for (int j = 1; j <= b.length(); j++)
                c[j] = Math.min(Math.min(c[j - 1] + 1, p[j] + 1), p[j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1));
            int[] t = p; p = c; c = t;
        }
        return p[b.length()];
    }

    /** Decodes UTF-8; falls back to windows-1252 (common for UK bank exports) when the bytes are not valid UTF-8. */
    static String decode(byte[] raw, String[] encOut) {
        String s;
        try {
            s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
            encOut[0] = "UTF-8";
        } catch (CharacterCodingException e) {
            s = new String(raw, Charset.forName("windows-1252"));
            encOut[0] = "windows-1252";
        }
        if (s.startsWith("﻿")) s = s.substring(1);
        return s;
    }

    /** RFC-4180 CSV parser that works on the whole text, so quoted fields may contain line breaks. */
    static List<List<String>> parseCsv(String text, char delim, List<Integer> startLines, int[] unterminatedAt) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder f = new StringBuilder();
        boolean q = false, any = false;
        int line = 1, rowStart = 1, quoteStart = 0;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (q) {
                if (ch == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') { f.append('"'); i++; }
                    else q = false;
                } else if (ch == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                    // normalise CRLF inside quotes
                } else {
                    if (ch == '\n') line++;
                    f.append(ch);
                }
            } else if (ch == '"') { q = true; any = true; quoteStart = line; }
            else if (ch == delim) { row.add(f.toString()); f.setLength(0); any = true; }
            else if (ch == '\r') { /* ignored outside quotes */ }
            else if (ch == '\n') {
                row.add(f.toString()); f.setLength(0);
                rows.add(row); startLines.add(rowStart);
                row = new ArrayList<>();
                line++; rowStart = line; any = false;
            } else { f.append(ch); any = true; }
        }
        if (q && unterminatedAt != null) unterminatedAt[0] = quoteStart;
        if (any || f.length() > 0 || !row.isEmpty()) { row.add(f.toString()); rows.add(row); startLines.add(rowStart); }
        return rows;
    }

    static boolean blankRow(List<String> r) {
        for (String s : r) if (!s.trim().isEmpty()) return false;
        return true;
    }

    static List<String> tokenize(String line) {
        List<String> r = new ArrayList<>();
        StringBuilder b = new StringBuilder();
        char q = 0;
        boolean has = false;
        for (char c : line.toCharArray()) {
            if (q != 0) { if (c == q) q = 0; else b.append(c); }
            else if (c == '"' || c == '\'') { q = c; has = true; }
            else if (Character.isWhitespace(c)) { if (has) { r.add(b.toString()); b.setLength(0); has = false; } }
            else { b.append(c); has = true; }
        }
        if (has) r.add(b.toString());
        return r;
    }

    static final List<Function<String, TemporalAccessor>> ISO_PARSERS = List.<Function<String, TemporalAccessor>>of(
            Instant::parse, OffsetDateTime::parse, ZonedDateTime::parse, LocalDateTime::parse, LocalDate::parse);

    static final String MAP_TEMPLATE = String.join("\n",
            "# Sherlock column-mapping profile",
            "# Use with:   java Sherlock.java --map this-file.properties statement.csv",
            "# Values are the column HEADERS in the bank's export (case-insensitive). Join several columns with +",
            "# (e.g. memo=Description+Reference). Delete what you do not need; lines starting with # are comments.",
            "",
            "name=Example bank statement",
            "",
            "# --- Transfer-style exports: one row = one payment between two accounts ---",
            "# id=Transaction ID",
            "# from=Payer account",
            "# to=Payee account",
            "# amount=Amount",
            "",
            "# --- Statement-style exports: one account's statement ---",
            "# The account this statement belongs to. Use the SAME identifier you use in your other files",
            "# (e.g. sort code + account number) so payments can be matched across banks.",
            "owner=12-34-56 12345678",
            "counterparty=Counterparty account",
            "# Either separate paid-out / paid-in columns ...",
            "debit=Paid out",
            "credit=Paid in",
            "# ... or one signed amount column (negative = money out):",
            "# amount=Amount",
            "# ... or an amount column plus a direction column:",
            "# direction=Type",
            "# direction.out=DEBIT,DR,OUT",
            "# direction.in=CREDIT,CR,IN",
            "",
            "# --- Date and time (java.time patterns) ---",
            "date=Date",
            "time=Time",
            "date.format=dd/MM/yyyy",
            "time.format=HH:mm[:ss]",
            "# or a single column:",
            "# timestamp=Posted",
            "# timestamp.format=dd/MM/yyyy HH:mm",
            "# Time zone the bank wrote the times in (UK exports are usually UK local time):",
            "tz=Europe/London",
            "",
            "# --- Optional columns ---",
            "memo=Description",
            "# currency=Currency",
            "# currency.default=GBP",
            "# ip=IP address",
            "# device=Device ID",
            "# In statement mode ip/device are only kept on money OUT (they describe the owner's own session).",
            "",
            "# --- File format ---",
            "# delimiter=,            (use tab for tab-separated files)",
            "# decimalcomma=false     (true for amounts like 1.234,56)",
            "# skiplines=0            (rows above the header, e.g. a bank's title lines)",
            "");

    // =====================================================================
    // The case: all loaded data, settings and analysis
    // =====================================================================
    static final class Case {
        final Settings s = new Settings();
        PrintStream out;
        final List<Tx> txs = new ArrayList<>();
        final Map<String, List<Tx>> inBy = new HashMap<>(), outBy = new HashMap<>();
        final Map<String, Tx> byId = new HashMap<>();
        final List<Source> sources = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();
        final List<String> skipped = new ArrayList<>();
        final List<String> merges = new ArrayList<>();
        final Map<String, TreeMap<LocalDate, BigDecimal>> rates = new TreeMap<>();
        final Map<String, String> watch = new TreeMap<>();
        final List<String> audit = new ArrayList<>();
        final Map<String, Param> params = new LinkedHashMap<>();
        final List<Detector> detectors = buildDetectors();
        String ratesInfo, watchInfo;
        boolean full = false;          // print every transaction id (reports)
        List<Finding> cache;
        List<String> notes = new ArrayList<>();
        Set<String> accountsCache;
        DateTimeFormatter tsf;
        ZoneId tsfZone;

        Case(PrintStream out) {
            this.out = out;
            buildParams();
        }

        // -----------------------------------------------------------------
        // Command line, shell and dispatcher
        // -----------------------------------------------------------------
        List<String> applyCommandLine(String[] args) throws Exception {
            audit("command line: " + String.join(" ", args));
            List<String[]> opts = new ArrayList<>(), files = new ArrayList<>();
            List<String> cmd = new ArrayList<>();
            String map = null;
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                if (a.startsWith("--")) {
                    String o = a.toLowerCase(Locale.ROOT);
                    if (o.equals("--decimal-comma") || o.equals("--no-dedupe")) { opts.add(new String[]{o, ""}); continue; }
                    if (i + 1 >= args.length) throw new IllegalArgumentException(a + " needs a value");
                    String v = args[++i];
                    if (o.equals("--map")) map = v; else opts.add(new String[]{o, v});
                } else if (Files.isRegularFile(Paths.get(a))) files.add(new String[]{a, map});
                else if (a.toLowerCase(Locale.ROOT).endsWith(".csv")) throw new IllegalArgumentException("file not found: " + a);
                else { cmd.addAll(Arrays.asList(args).subList(i, args.length)); break; }
            }
            if (files.isEmpty())
                throw new IllegalArgumentException("no input file. Usage: java Sherlock.java [options] <file.csv>... [command]");
            for (String[] o : opts) if (o[0].equals("--config")) loadConfig(Paths.get(o[1]));
            String rateFile = null, watchFile = null;
            for (String[] o : opts) {
                switch (o[0]) {
                    case "--config": break;
                    case "--tz": setParam("tz", o[1], false); break;
                    case "--base": setParam("base", o[1], false); break;
                    case "--analyst": setParam("analyst", o[1], false); break;
                    case "--decimal-comma": setParam("decimalcomma", "true", false); break;
                    case "--no-dedupe": setParam("dedupe", "false", false); break;
                    case "--rates": rateFile = o[1]; break;
                    case "--watchlist": watchFile = o[1]; break;
                    default: throw new IllegalArgumentException("unknown option " + o[0]);
                }
            }
            for (String[] f : files) loadFile(Paths.get(f[0]), f[1] == null ? null : Paths.get(f[1]));
            if (rateFile != null) loadRates(Paths.get(rateFile));
            if (watchFile != null) loadWatchlist(Paths.get(watchFile));
            return cmd;
        }

        void usage() {
            out.println(String.join("\n",
                    "",
                    "SHERLOCK " + VERSION + " - financial crime investigation assistant",
                    "",
                    "DATA",
                    "  summary                          sources with SHA-256 hashes, period, totals, warnings",
                    "  load <file.csv> [mapping]        add another export or statement (cross-file duplicates are merged)",
                    "  dupes                            payments merged as duplicates across files",
                    "  skipped                          every row that could not be loaded, and why",
                    "  rates <rates.csv>                load exchange rates (date,currency,rate) and convert to the base currency",
                    "  watchlist <watchlist.csv>        load known accounts / IPs / devices (type,value,note)",
                    "ANALYSIS",
                    "  analyze [all]                    rank suspicious accounts, then list possible victims",
                    "  findings <TYPE>                  every finding of one type, e.g. findings STRUCTURING",
                    "  victims                          safeguarding list: likely victims and compromised accounts",
                    "  links                            clusters of accounts linked by shared device / IP",
                    "  account <account>                profile of one account (names can be partial / any case)",
                    "  timeline <account>               chronological history with running net position",
                    "  detectors | enable <name> | disable <name>",
                    "TRACING",
                    "  trace <account> [account...] [since <time>]   follow victims' money forward to where it is now",
                    "  tracetx <txid> [txid...]         trace from specific payments",
                    "  compare <account> [account...]   where the money ends up under each tracing rule",
                    "  reverse <account>                where the money received by an account originally came from",
                    "OUTPUT",
                    "  report <file.txt|file.html> [victim...]   full report (HTML adds a Sankey diagram and charts)",
                    "  export dot <file.dot> [victim...]         Graphviz graph (whole case, or only the traced money)",
                    "  export csv <prefix> [victim...]           entity + link CSVs for i2 Analyst's Notebook / Gephi",
                    "  export tx <file.csv>                      normalised, de-duplicated transactions",
                    "  audit [file]                              log of every command run this session",
                    "SETTINGS",
                    "  settings                         every setting with its current value",
                    "  set <name> <value>               e.g. set tracemode prorata | set threshold 10000,25000",
                    "  config <file.properties>         load settings     saveconfig <file.properties>   save them",
                    "  help | quit",
                    "",
                    "Start with:  java Sherlock.java [--tz Europe/London] <file.csv>      Demo: java Sherlock.java demo demo.csv",
                    ""));
        }

        void shell() throws IOException {
            out.println("\nSHERLOCK " + VERSION + " ready. Type 'help' for commands, 'quit' to leave.\n");
            summary();
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            while (true) {
                out.print("\nsherlock> ");
                out.flush();
                String line = br.readLine();
                if (line == null) break;
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.equalsIgnoreCase("quit") || line.equalsIgnoreCase("exit")) break;
                try { exec(tokenize(line)); }
                catch (Exception e) { out.println("Error: " + e.getMessage()); }
            }
        }

        void exec(List<String> a) throws Exception {
            if (a.isEmpty()) return;
            audit(a.stream().map(x -> x.contains(" ") ? "\"" + x + "\"" : x).collect(Collectors.joining(" ")));
            switch (a.get(0).toLowerCase(Locale.ROOT)) {
                case "help": usage(); break;
                case "summary": summary(); break;
                case "load":
                    need(a, 2, "load <file.csv> [mapping.properties]");
                    loadFile(Paths.get(a.get(1)), a.size() > 2 ? Paths.get(a.get(2)) : null);
                    Source src = sources.get(sources.size() - 1);
                    out.println("Loaded " + src.name + ": " + src.loaded + " new, " + src.merged + " merged as duplicates, "
                            + src.skipped + " skipped.");
                    break;
                case "dupes": listMerges(); break;
                case "skipped": listSkipped(); break;
                case "rates": need(a, 2, "rates <rates.csv>"); loadRates(Paths.get(a.get(1))); out.println(ratesInfo); break;
                case "watchlist": need(a, 2, "watchlist <file.csv>"); loadWatchlist(Paths.get(a.get(1))); out.println(watchInfo); break;
                case "analyze": case "analyse": analyze(a.size() > 1 && a.get(1).equalsIgnoreCase("all")); break;
                case "findings": need(a, 2, "findings <TYPE>"); findingsOfType(a.get(1)); break;
                case "victims": printSafeguarding(); break;
                case "links": links(); break;
                case "account": need(a, 2, "account <account>"); account(resolve(a.get(1))); break;
                case "timeline": need(a, 2, "timeline <account>"); timeline(resolve(a.get(1))); break;
                case "detectors": listDetectors(); break;
                case "enable": case "disable": {
                    need(a, 2, a.get(0) + " <detector>");
                    String n = a.get(1).toLowerCase(Locale.ROOT);
                    if (detectors.stream().noneMatch(d -> d.name.equals(n)))
                        throw new IllegalArgumentException("no detector '" + n + "' - see 'detectors'");
                    if (a.get(0).equalsIgnoreCase("enable")) s.disabled.remove(n); else s.disabled.add(n);
                    cache = null;
                    out.println("OK: " + n + (s.disabled.contains(n) ? " disabled" : " enabled"));
                    break;
                }
                case "trace": {
                    need(a, 2, "trace <account> [account...] [since <time>]");
                    List<String> vs = new ArrayList<>();
                    Instant since = null;
                    for (int i = 1; i < a.size(); i++) {
                        String x = a.get(i);
                        if (x.equalsIgnoreCase("since")) {
                            need(a, i + 2, "trace <account> ... since <time>");
                            since = parseUserTime(String.join(" ", a.subList(i + 1, a.size())));
                            break;
                        }
                        if (i > 1 && !accounts().contains(x) && looksLikeTime(x)) {
                            since = parseUserTime(String.join(" ", a.subList(i, a.size())));
                            break;
                        }
                        vs.add(resolve(x));
                    }
                    Trace t = runTrace(seedsFor(vs, since), s.traceMode, null);
                    t.label = "all payments out of " + String.join(", ", vs) + (since == null ? "" : " since " + ts(since));
                    printTrace(t);
                    break;
                }
                case "tracetx": {
                    need(a, 2, "tracetx <txid> [txid...]");
                    Map<Tx, String> seeds = new IdentityHashMap<>();
                    for (String id : a.subList(1, a.size())) {
                        Tx t = byId.get(id);
                        if (t == null) out.println("No transaction with id " + id); else seeds.put(t, t.from);
                    }
                    if (seeds.isEmpty()) break;
                    Trace t = runTrace(seeds, s.traceMode, null);
                    t.label = "transactions " + String.join(", ", a.subList(1, a.size()));
                    printTrace(t);
                    break;
                }
                case "compare": {
                    need(a, 2, "compare <account> [account...]");
                    List<String> vs = new ArrayList<>();
                    for (String x : a.subList(1, a.size())) vs.add(resolve(x));
                    compare(seedsFor(vs, null), String.join(", ", vs));
                    break;
                }
                case "reverse": need(a, 2, "reverse <account>"); reverse(resolve(a.get(1))); break;
                case "report": {
                    need(a, 2, "report <file.txt|file.html> [victim...]");
                    List<String> vs = new ArrayList<>();
                    for (String x : a.subList(2, a.size())) vs.add(resolve(x));
                    report(Paths.get(a.get(1)), vs);
                    break;
                }
                case "export": export(a); break;
                case "audit":
                    if (a.size() > 1) {
                        Files.write(Paths.get(a.get(1)), (String.join(System.lineSeparator(), audit) + System.lineSeparator())
                                .getBytes(StandardCharsets.UTF_8));
                        out.println("Audit log written to " + a.get(1));
                    } else { out.println("== AUDIT LOG =="); audit.forEach(out::println); }
                    break;
                case "settings": printSettings(); break;
                case "set":
                    need(a, 3, "set <name> <value>   (see 'settings')");
                    setParam(a.get(1).toLowerCase(Locale.ROOT), String.join(" ", a.subList(2, a.size())), true);
                    break;
                case "config": need(a, 2, "config <file.properties>"); loadConfig(Paths.get(a.get(1))); out.println("Settings loaded from " + a.get(1)); break;
                case "saveconfig": need(a, 2, "saveconfig <file.properties>"); saveConfig(Paths.get(a.get(1))); break;
                default: out.println("Unknown command '" + a.get(0) + "'. Type 'help'.");
            }
        }

        void need(List<String> a, int n, String usage) {
            if (a.size() < n) throw new IllegalArgumentException("usage: " + usage);
        }

        void audit(String line) {
            audit.add(Instant.now().truncatedTo(ChronoUnit.SECONDS) + "  " + line);
        }

        String ts(Instant i) {
            if (tsf == null || !s.tz.equals(tsfZone)) {
                tsf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(s.tz);
                tsfZone = s.tz;
            }
            return tsf.format(i);
        }

        String fmtIds(List<String> ids) {
            if (ids.isEmpty()) return "";
            if (full || ids.size() <= 8) return String.join(", ", ids);
            return String.join(", ", ids.subList(0, 8)) + " ... (+" + (ids.size() - 8) + " more)";
        }

        Set<String> accounts() {
            if (accountsCache == null) {
                Set<String> a = new TreeSet<>();
                for (Tx t : txs) { a.add(t.from); a.add(t.to); }
                accountsCache = a;
            }
            return accountsCache;
        }

        /** Exact match, then case-insensitive, then a unique partial match; otherwise suggests close names. */
        String resolve(String in) {
            Set<String> all = accounts();
            if (all.contains(in)) return in;
            List<String> ci = all.stream().filter(x -> x.equalsIgnoreCase(in)).collect(Collectors.toList());
            if (ci.size() == 1) { out.println("(using " + ci.get(0) + ")"); return ci.get(0); }
            String low = in.toLowerCase(Locale.ROOT);
            List<String> sub = all.stream().filter(x -> x.toLowerCase(Locale.ROOT).contains(low)).collect(Collectors.toList());
            if (sub.size() == 1) { out.println("(using " + sub.get(0) + ")"); return sub.get(0); }
            if (sub.size() > 1)
                throw new IllegalArgumentException("'" + in + "' matches " + sub.size() + " accounts: "
                        + String.join(", ", sub.subList(0, Math.min(10, sub.size()))) + (sub.size() > 10 ? ", ..." : ""));
            List<String> close = all.stream()
                    .sorted(Comparator.comparingInt((String x) -> lev(x.toLowerCase(Locale.ROOT), low)).thenComparing(x -> x))
                    .limit(5).collect(Collectors.toList());
            throw new IllegalArgumentException("account '" + in + "' not found. Did you mean: " + String.join(", ", close) + "?");
        }

        boolean looksLikeTime(String x) {
            try { parseUserTime(x); return true; } catch (Exception e) { return false; }
        }

        Instant parseUserTime(String x) { return parseTime(x, null, s.tz, null, null); }

        // -----------------------------------------------------------------
        // Settings
        // -----------------------------------------------------------------
        void p(String name, String help, Supplier<String> get, Consumer<String> set) {
            params.put(name, new Param(name, help, get, set));
        }

        static int posInt(String v) {
            int i = Integer.parseInt(v.trim());
            if (i < 1) throw new IllegalArgumentException("must be 1 or more");
            return i;
        }

        static double fraction(String v) {
            double d = Double.parseDouble(v.trim());
            if (d <= 0 || d > 1) throw new IllegalArgumentException("must be between 0 and 1");
            return d;
        }

        static long moneyArg(String v) {
            long m = minor(parseAmount(v, false));
            if (m <= 0) throw new IllegalArgumentException("must be positive");
            return m;
        }

        void buildParams() {
            p("threshold", "structuring threshold(s) to stay under, comma-separated (base currency)",
                    () -> s.thresholds.stream().map(Sherlock::plain).collect(Collectors.joining(",")),
                    v -> { List<Long> l = new ArrayList<>(); for (String x : v.split(",")) l.add(moneyArg(x)); s.thresholds = l; });
            p("structband", "lower edge of the 'just under' band, as a fraction of the threshold",
                    () -> num(s.structBand), v -> s.structBand = fraction(v));
            p("structmin", "minimum number of just-under payments", () -> "" + s.structMin, v -> s.structMin = posInt(v));
            p("structwindow", "structuring window (hours)", () -> "" + s.structWindowHours, v -> s.structWindowHours = posInt(v));
            p("passratio", "pass-through: share of incoming money forwarded on", () -> num(s.passRatio), v -> s.passRatio = fraction(v));
            p("passmin", "ignore accounts / bursts / patterns below this total", () -> plain(s.passMin), v -> s.passMin = moneyArg(v));
            p("dwell", "pass-through: maximum average holding time (hours)", () -> "" + s.dwellHours, v -> s.dwellHours = posInt(v));
            p("fanmin", "fan-in / fan-out: distinct counterparties in the window", () -> "" + s.fanMin, v -> s.fanMin = posInt(v));
            p("fanwindow", "fan-in / fan-out window (days)", () -> "" + s.fanWindowDays, v -> s.fanWindowDays = posInt(v));
            p("devicemin", "accounts sharing one device", () -> "" + s.deviceMin, v -> s.deviceMin = posInt(v));
            p("ipmin", "accounts sharing one IP (weaker signal)", () -> "" + s.ipMin, v -> s.ipMin = posInt(v));
            p("cyclelen", "longest loop searched for (accounts)", () -> "" + s.cycleMaxLen, v -> s.cycleMaxLen = posInt(v));
            p("cyclewindow", "maximum time between consecutive hops of a loop (hours)", () -> "" + s.cycleWindowHours,
                    v -> s.cycleWindowHours = posInt(v));
            p("cyclemin", "smallest payment counted as a loop hop", () -> plain(s.cycleMin), v -> s.cycleMin = moneyArg(v));
            p("victimmin", "victim pattern: payments to one payee in the window", () -> "" + s.victimMin, v -> s.victimMin = posInt(v));
            p("victimwindow", "victim pattern window (days)", () -> "" + s.victimWindowDays, v -> s.victimWindowDays = posInt(v));
            p("keywords", "memo keywords typical of scam payments, comma-separated", () -> String.join(",", s.keywords),
                    v -> s.keywords = Arrays.stream(v.split(",")).map(x -> x.trim().toLowerCase(Locale.ROOT))
                            .filter(x -> !x.isEmpty()).collect(Collectors.toCollection(ArrayList::new)));
            p("atohistory", "account takeover: earlier payments needed to know the usual device", () -> "" + s.atoHistory,
                    v -> s.atoHistory = posInt(v));
            p("atowindow", "account takeover: hours after a new device in which a large payment counts", () -> "" + s.atoWindowHours,
                    v -> s.atoWindowHours = posInt(v));
            p("atofactor", "account takeover: 'large' = this many times the usual median payment", () -> num(s.atoFactor),
                    v -> { double d = Double.parseDouble(v); if (d <= 1) throw new IllegalArgumentException("must be above 1"); s.atoFactor = d; });
            p("dormantdays", "dormant account: days of silence before a burst", () -> "" + s.dormantDays, v -> s.dormantDays = posInt(v));
            p("burstdays", "dormant account: length of the burst after waking (days)", () -> "" + s.burstDays, v -> s.burstDays = posInt(v));
            p("roundunit", "round amounts: exact multiples of this", () -> plain(s.roundUnit), v -> s.roundUnit = moneyArg(v));
            p("roundratio", "round amounts: share of an account's payments that are round", () -> num(s.roundRatio),
                    v -> s.roundRatio = fraction(v));
            p("roundmin", "round amounts: minimum number of round payments", () -> "" + s.roundMin, v -> s.roundMin = posInt(v));
            p("repeatmin", "repeat amounts: identical payments in the window", () -> "" + s.repeatMin, v -> s.repeatMin = posInt(v));
            p("repeatwindow", "repeat amounts window (days)", () -> "" + s.repeatWindowDays, v -> s.repeatWindowDays = posInt(v));
            p("repeatminamount", "repeat amounts: ignore payments below this", () -> plain(s.repeatMinAmount),
                    v -> s.repeatMinAmount = moneyArg(v));
            p("tracemode", "tracing rule: " + String.join(" | ", MODES), () -> s.traceMode, v -> {
                String m = v.trim().toLowerCase(Locale.ROOT);
                if (!MODES.contains(m)) throw new IllegalArgumentException("tracemode must be one of " + MODES);
                s.traceMode = m;
            });
            p("dedupe", "merge the same payment found in several files (true/false)", () -> "" + s.dedupe,
                    v -> s.dedupe = bool(v));
            p("dedupewindow", "duplicates: maximum time difference between the two records (hours)", () -> "" + s.dedupeWindowHours,
                    v -> s.dedupeWindowHours = posInt(v));
            p("base", "base currency that every amount is converted to", () -> s.base, v -> {
                String c = v.trim().toUpperCase(Locale.ROOT);
                if (!c.matches("[A-Z]{3,5}")) throw new IllegalArgumentException("currency code expected, e.g. GBP");
                s.base = c;
                reconvert();
            });
            p("tz", "time zone for display, for 'since' and for files loaded from now on", () -> s.tz.toString(), v -> {
                s.tz = ZoneId.of(v.trim());
                s.tzExplicit = true;
                reconvert();
            });
            p("decimalcomma", "read amounts like 1.234,56 in files loaded from now on (true/false)", () -> "" + s.decimalComma,
                    v -> s.decimalComma = bool(v));
            p("analyst", "name stamped on reports", () -> s.analyst, v -> s.analyst = v.trim());
        }

        static boolean bool(String v) {
            String x = v.trim().toLowerCase(Locale.ROOT);
            if (x.equals("true") || x.equals("yes") || x.equals("on") || x.equals("1")) return true;
            if (x.equals("false") || x.equals("no") || x.equals("off") || x.equals("0")) return false;
            throw new IllegalArgumentException("true or false expected");
        }

        void setParam(String name, String value, boolean echo) {
            Param p = params.get(name);
            if (p == null) throw new IllegalArgumentException("unknown setting '" + name + "' - see 'settings'");
            try { p.set.accept(value); }
            catch (IllegalArgumentException | DateTimeException e) {
                throw new IllegalArgumentException("bad value for " + name + ": " + e.getMessage());
            }
            cache = null;
            if (echo) {
                out.println("OK: " + name + " = " + p.get.get());
                if (name.equals("tz") || name.equals("decimalcomma"))
                    out.println("(files already loaded keep the way they were read; this applies to display and to new files)");
            }
        }

        void printSettings() {
            out.println("== SETTINGS ==");
            for (Param p : params.values()) out.println(String.format("  %-16s %-28s %s", p.name, clip(p.get.get(), 28), p.help));
            out.println("  disabled detectors: " + (s.disabled.isEmpty() ? "none" : String.join(", ", s.disabled)));
        }

        void loadConfig(Path p) throws IOException {
            Properties pr = new Properties();
            try (Reader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) { pr.load(r); }
            for (String k : new TreeSet<>(pr.stringPropertyNames())) {
                if (k.equals("disabled")) {
                    s.disabled.clear();
                    for (String d : pr.getProperty(k).split(",")) if (!d.trim().isEmpty()) s.disabled.add(d.trim().toLowerCase(Locale.ROOT));
                    continue;
                }
                setParam(k.toLowerCase(Locale.ROOT), pr.getProperty(k), false);
            }
            cache = null;
            audit("settings loaded from " + p);
        }

        void saveConfig(Path p) throws IOException {
            StringBuilder b = new StringBuilder("# Sherlock " + VERSION + " settings, saved " + Instant.now().truncatedTo(ChronoUnit.SECONDS) + "\n");
            for (Param x : params.values()) {
                b.append("# ").append(x.help).append('\n');
                b.append(x.name).append('=').append(x.get.get().replace("\\", "\\\\")).append("\n");
            }
            b.append("# detectors switched off\ndisabled=").append(String.join(",", s.disabled)).append('\n');
            Files.write(p, b.toString().getBytes(StandardCharsets.UTF_8));
            out.println("Settings saved to " + p);
        }

        // -----------------------------------------------------------------
        // Loading
        // -----------------------------------------------------------------
        static Mapping loadMapping(Path p) throws IOException {
            Properties pr = new Properties();
            try (Reader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) { pr.load(r); }
            Mapping m = new Mapping();
            m.standard = false;
            m.name = pr.getProperty("name", p.getFileName().toString()).trim();
            for (String k : pr.stringPropertyNames()) {
                String key = k.toLowerCase(Locale.ROOT), v = pr.getProperty(k).trim();
                if (FIELDS.contains(key)) { if (!v.isEmpty()) m.cols.put(key, v); continue; }
                if (!MAP_SETTINGS.contains(key))
                    throw new IllegalArgumentException(p + ": unknown key '" + k + "' (see 'java Sherlock.java maptemplate')");
                switch (key) {
                    case "owner": m.owner = v.isEmpty() ? null : v; break;
                    case "timestamp.format": m.tsFormat = v; break;
                    case "date.format": m.dateFormat = v; break;
                    case "time.format": m.timeFormat = v; break;
                    case "delimiter":
                        m.delimiter = v.equalsIgnoreCase("tab") || v.equals("\t") ? '\t' : v.equalsIgnoreCase("semicolon") ? ';' : v.charAt(0);
                        break;
                    case "decimalcomma": m.decimalComma = bool(v); break;
                    case "tz": m.tz = ZoneId.of(v); break;
                    case "skiplines": m.skipLines = Integer.parseInt(v); break;
                    case "currency.default": m.defaultCurrency = v.toUpperCase(Locale.ROOT); break;
                    case "direction.out": m.dirOut = upperSet(v); break;
                    case "direction.in": m.dirIn = upperSet(v); break;
                    default:
                }
            }
            return m;
        }

        static Set<String> upperSet(String v) {
            Set<String> r = new HashSet<>();
            for (String x : v.split(",")) if (!x.trim().isEmpty()) r.add(x.trim().toUpperCase(Locale.ROOT));
            return r;
        }

        void loadFile(Path p, Path mapPath) throws Exception {
            Mapping m = mapPath == null ? new Mapping() : loadMapping(mapPath);
            byte[] raw = Files.readAllBytes(p);
            String hash = sha256(raw);
            for (Source x : sources)
                if (x.hash.equals(hash)) throw new IllegalArgumentException(p + " is identical to " + x.name + " (same SHA-256) - not loaded twice");
            Source src = new Source();
            src.path = p.toAbsolutePath().toString();
            src.hash = hash;
            src.mapping = mapPath == null ? "standard columns"
                    : m.name + " (" + mapPath.getFileName() + ", sha256 " + sha256(Files.readAllBytes(mapPath)).substring(0, 16) + "...)";
            String base = p.getFileName().toString(), nm = base;
            for (int n = 2; sourceNamed(nm); n++) nm = base + "#" + n;
            src.name = nm;
            String[] enc = new String[1];
            String text = decode(raw, enc);
            src.encoding = enc[0];
            if (!enc[0].equals("UTF-8"))
                warnings.add(src.name + ": not valid UTF-8, read as windows-1252 (common in UK bank exports) - check pound signs and names");
            ZoneId zone = m.tz != null ? m.tz : s.tz;
            src.zone = zone.toString();
            src.explicitZone = m.tz != null || s.tzExplicit;
            boolean dc = m.decimalComma != null ? m.decimalComma : s.decimalComma;

            List<Integer> starts = new ArrayList<>();
            int[] unterminated = {0};
            List<List<String>> rows = parseCsv(text, m.delimiter, starts, unterminated);
            if (unterminated[0] > 0)
                warnings.add(src.name + ": a quoted field opened on line " + unterminated[0] + " is never closed - the rest of the file was read as one field");
            int hrow = Math.max(0, m.skipLines);
            while (hrow < rows.size() && blankRow(rows.get(hrow))) hrow++;
            if (hrow >= rows.size()) throw new IOException(p + ": no header row");
            Map<String, Integer> header = new HashMap<>();
            List<String> hr = rows.get(hrow);
            for (int i = 0; i < hr.size(); i++) header.putIfAbsent(hr.get(i).trim().toLowerCase(Locale.ROOT), i);

            Map<String, int[]> cols = new HashMap<>();
            for (String f : FIELDS) {
                String spec = m.cols.getOrDefault(f, m.standard ? f : null);
                if (spec == null) continue;
                String[] parts = spec.split("\\+");
                int[] idx = new int[parts.length];
                boolean ok = true;
                for (int i = 0; i < parts.length; i++) {
                    Integer ix = header.get(parts[i].trim().toLowerCase(Locale.ROOT));
                    if (ix == null) { ok = false; break; }
                    idx[i] = ix;
                }
                if (ok) cols.put(f, idx);
                else if (!m.standard) throw new IOException(p + ": mapping '" + m.name + "' expects column '" + spec + "' for " + f
                        + " but the header is " + hr);
            }
            boolean statement = m.owner != null;
            if (!cols.containsKey("timestamp") && !cols.containsKey("date"))
                throw new IOException(p + ": missing required column: timestamp (or date)");
            if (statement) {
                if (!cols.containsKey("counterparty")) throw new IOException(p + ": statement mapping needs a counterparty column");
                if (!cols.containsKey("amount") && !cols.containsKey("debit") && !cols.containsKey("credit"))
                    throw new IOException(p + ": statement mapping needs amount, or debit/credit columns");
            } else {
                for (String req : new String[]{"from", "to", "amount"})
                    if (!cols.containsKey(req)) throw new IOException(p + ": missing required column: " + req
                            + (m.standard ? " (for other layouts write a mapping file: java Sherlock.java maptemplate)" : ""));
            }
            DateTimeFormatter fTs = m.tsFormat == null ? null : DateTimeFormatter.ofPattern(m.tsFormat, Locale.UK);
            DateTimeFormatter fDate = m.dateFormat == null ? null : DateTimeFormatter.ofPattern(m.dateFormat, Locale.UK);
            DateTimeFormatter fDateTime = m.dateFormat == null ? null
                    : DateTimeFormatter.ofPattern(m.dateFormat + " " + (m.timeFormat == null ? "HH:mm[:ss]" : m.timeFormat), Locale.UK);

            List<Tx> fresh = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (int r = hrow + 1; r < rows.size(); r++) {
                List<String> f = rows.get(r);
                int line = starts.get(r);
                if (blankRow(f)) continue;
                src.rows++;
                String ref = src.name + ":" + line;
                try {
                    Tx t = parseRow(f, cols, m, statement, src, line, zone, dc, fTs, fDate, fDateTime, ref);
                    if (!seen.add(t.id)) throw new IllegalArgumentException("duplicate id " + t.id + " within this file");
                    fresh.add(t);
                } catch (Exception e) {
                    skipped.add(ref + "  " + e.getMessage());
                    src.skipped++;
                }
            }
            sources.add(src);
            src.loaded = addAll(src, fresh);
            reconvert();
            rebuild();
            audit("loaded " + src.name + " (" + src.path + ") sha256=" + hash + " mapping=" + src.mapping + " encoding="
                    + src.encoding + " zone=" + src.zone + " rows=" + src.rows + " new=" + src.loaded + " merged=" + src.merged
                    + " skipped=" + src.skipped);
        }

        boolean sourceNamed(String n) {
            for (Source x : sources) if (x.name.equals(n)) return true;
            return false;
        }

        static String val(List<String> f, Map<String, int[]> cols, String k) {
            int[] idx = cols.get(k);
            if (idx == null) return "";
            StringBuilder b = new StringBuilder();
            for (int i : idx) {
                String v = i < f.size() ? f.get(i).trim() : "";
                if (v.isEmpty()) continue;
                if (b.length() > 0) b.append(' ');
                b.append(v);
            }
            return b.toString();
        }

        Tx parseRow(List<String> f, Map<String, int[]> cols, Mapping m, boolean statement, Source src, int line, ZoneId zone,
                    boolean dc, DateTimeFormatter fTs, DateTimeFormatter fDate, DateTimeFormatter fDateTime, String ref) {
            Instant time;
            if (cols.containsKey("timestamp")) time = parseTime(val(f, cols, "timestamp"), fTs, zone, src, ref);
            else {
                String d = val(f, cols, "date"), tm = val(f, cols, "time");
                time = parseTime(tm.isEmpty() ? d : d + " " + tm, tm.isEmpty() ? fDate : fDateTime, zone, src, ref);
            }
            String from, to, ip = val(f, cols, "ip"), device = val(f, cols, "device");
            BigDecimal amt;
            if (statement) {
                String cp = val(f, cols, "counterparty");
                if (cp.isEmpty()) throw new IllegalArgumentException("blank counterparty");
                boolean outflow;
                String deb = val(f, cols, "debit"), cre = val(f, cols, "credit");
                BigDecimal dv = deb.isEmpty() ? null : parseAmount(deb, dc), cv = cre.isEmpty() ? null : parseAmount(cre, dc);
                if (dv != null && dv.signum() == 0) dv = null;
                if (cv != null && cv.signum() == 0) cv = null;
                if (dv != null || cv != null) {
                    if (dv != null && cv != null) throw new IllegalArgumentException("both paid-out and paid-in are filled in");
                    outflow = dv != null;
                    amt = (dv != null ? dv : cv).abs();
                } else {
                    if (!cols.containsKey("amount")) throw new IllegalArgumentException("no amount in paid-out or paid-in");
                    BigDecimal a = parseAmount(val(f, cols, "amount"), dc);
                    if (a.signum() == 0) throw new IllegalArgumentException("zero amount");
                    if (cols.containsKey("direction")) {
                        String dir = val(f, cols, "direction").toUpperCase(Locale.ROOT);
                        if (m.dirOut.contains(dir)) outflow = true;
                        else if (m.dirIn.contains(dir)) outflow = false;
                        else throw new IllegalArgumentException("unknown direction '" + dir + "' (set direction.out / direction.in)");
                    } else outflow = a.signum() < 0;
                    amt = a.abs();
                }
                from = outflow ? m.owner : cp;
                to = outflow ? cp : m.owner;
                if (!outflow) { ip = ""; device = ""; }   // the owner's session says nothing about the sender
            } else {
                from = val(f, cols, "from");
                to = val(f, cols, "to");
                if (from.isEmpty() || to.isEmpty()) throw new IllegalArgumentException("blank from/to");
                amt = parseAmount(val(f, cols, "amount"), dc);
                if (amt.signum() <= 0) throw new IllegalArgumentException("non-positive amount");
            }
            String id = val(f, cols, "id");
            if (id.isEmpty()) id = src.name + ":" + line;
            String cur = val(f, cols, "currency").toUpperCase(Locale.ROOT);
            if (cur.isEmpty()) cur = m.defaultCurrency;
            return new Tx(src.name, line, id, time, from, to, amt, cur, ip, device, val(f, cols, "memo"));
        }

        Instant parseTime(String raw, DateTimeFormatter fmt, ZoneId zone, Source src, String ref) {
            String x = raw.trim();
            if (x.isEmpty()) throw new IllegalArgumentException("blank timestamp");
            TemporalAccessor ta = null;
            if (fmt != null) {
                try { ta = fmt.parseBest(x, ZonedDateTime::from, OffsetDateTime::from, LocalDateTime::from, LocalDate::from); }
                catch (DateTimeException e) {
                    throw new IllegalArgumentException("timestamp '" + x + "' does not match the format in the mapping file");
                }
            } else {
                String y = x.replace(' ', 'T');
                for (Function<String, TemporalAccessor> pf : ISO_PARSERS) {
                    try { ta = pf.apply(y); break; } catch (DateTimeException ignored) { }
                }
                if (ta == null)
                    throw new IllegalArgumentException("unreadable timestamp '" + x + "' (not ISO-8601 - describe the format in a"
                            + " mapping file: java Sherlock.java maptemplate)");
            }
            if (ta instanceof Instant) { if (src != null) src.zoned++; return (Instant) ta; }
            if (ta instanceof ZonedDateTime) { if (src != null) src.zoned++; return ((ZonedDateTime) ta).toInstant(); }
            if (ta instanceof OffsetDateTime) { if (src != null) src.zoned++; return ((OffsetDateTime) ta).toInstant(); }
            LocalDateTime ldt = ta instanceof LocalDate ? ((LocalDate) ta).atStartOfDay() : (LocalDateTime) ta;
            if (src != null) src.zoneless++;
            List<ZoneOffset> offs = zone.getRules().getValidOffsets(ldt);
            if (ref != null && offs.size() > 1)
                warnings.add(ref + ": local time " + ldt + " happens twice when the clocks go back - the earlier one was used");
            else if (ref != null && offs.isEmpty())
                warnings.add(ref + ": local time " + ldt + " does not exist (the clocks went forward) - moved forward by the gap");
            return ZonedDateTime.of(ldt, zone).toInstant();
        }

        /** Adds a file's rows, merging any that are the same payment as one already loaded from another file. */
        int addAll(Source src, List<Tx> fresh) {
            Map<String, List<Tx>> idx = new HashMap<>();
            if (s.dedupe) for (Tx t : txs) idx.computeIfAbsent(dkey(t), k -> new ArrayList<>()).add(t);
            Set<Tx> used = Collections.newSetFromMap(new IdentityHashMap<>());
            fresh.sort(Comparator.comparing((Tx t) -> t.time).thenComparingInt(t -> t.line));
            int added = 0;
            for (Tx t : fresh) {
                if (s.dedupe) {
                    Tx best = null;
                    long bestD = Long.MAX_VALUE;
                    for (Tx c : idx.getOrDefault(dkey(t), List.of())) {
                        if (used.contains(c)) continue;
                        long d = Math.abs(secs(c.time, t.time));
                        if (d <= s.dedupeWindowHours * 3600L && d < bestD) { best = c; bestD = d; }
                    }
                    if (best != null) {
                        used.add(best);
                        merge(best, t, bestD);
                        src.merged++;
                        continue;
                    }
                }
                if (byId.containsKey(t.id)) {
                    String old = t.id;
                    t.id = t.id + "@" + src.name;
                    warnings.add(t.ref() + ": id " + old + " is already used by " + byId.get(old).ref()
                            + " for a different payment - renamed " + t.id);
                }
                txs.add(t);
                byId.put(t.id, t);
                added++;
            }
            return added;
        }

        String dkey(Tx t) {
            return t.from + "\u0001" + t.to + "\u0001" + t.amount.stripTrailingZeros().toPlainString() + "\u0001" + t.cur(s.base);
        }

        void merge(Tx kept, Tx dup, long dSecs) {
            List<String> filled = new ArrayList<>();
            if (kept.ip.isEmpty() && !dup.ip.isEmpty()) { kept.ip = dup.ip; filled.add("ip"); }
            if (kept.device.isEmpty() && !dup.device.isEmpty()) { kept.device = dup.device; filled.add("device"); }
            if (kept.memo.isEmpty() && !dup.memo.isEmpty()) { kept.memo = dup.memo; filled.add("memo"); }
            kept.mergedFrom += (kept.mergedFrom.isEmpty() ? "" : "; ") + dup.id + " (" + dup.ref() + ")";
            merges.add(kept.id + " (" + kept.ref() + ") = " + (dup.id.equals(dup.ref()) ? dup.ref() : dup.id + " (" + dup.ref() + ")")
                    + "  " + kept.from + " -> " + kept.to + " "
                    + kept.amount.toPlainString() + " " + kept.cur(s.base) + ", recorded " + dur(dSecs) + " apart"
                    + (filled.isEmpty() ? "" : "; filled from the duplicate: " + String.join(", ", filled)));
        }

        void rebuild() {
            Map<String, Integer> order = new HashMap<>();
            for (int i = 0; i < sources.size(); i++) order.put(sources.get(i).name, i);
            txs.sort(Comparator.comparing((Tx t) -> t.time).thenComparingInt(t -> order.getOrDefault(t.src, 0))
                    .thenComparingInt(t -> t.line));
            inBy.clear();
            outBy.clear();
            for (Tx t : txs) {
                outBy.computeIfAbsent(t.from, k -> new ArrayList<>()).add(t);
                inBy.computeIfAbsent(t.to, k -> new ArrayList<>()).add(t);
            }
            accountsCache = null;
            cache = null;
        }

        void reconvert() {
            for (Tx t : txs) {
                String cur = t.cur(s.base);
                t.rate = null; t.rateDate = null; t.laterRate = false;
                if (cur.equals(s.base)) { t.value = minor(t.amount); t.converted = true; continue; }
                TreeMap<LocalDate, BigDecimal> r = rates.get(cur);
                LocalDate d = LocalDate.ofInstant(t.time, s.tz);
                Map.Entry<LocalDate, BigDecimal> e = r == null ? null : r.floorEntry(d);
                if (e == null && r != null) { e = r.ceilingEntry(d); t.laterRate = e != null; }
                if (e == null) { t.value = minor(t.amount); t.converted = false; }
                else { t.value = minor(t.amount.multiply(e.getValue())); t.converted = true; t.rate = e.getValue(); t.rateDate = e.getKey(); }
            }
            cache = null;
        }

        void loadRates(Path p) throws Exception {
            byte[] raw = Files.readAllBytes(p);
            String[] enc = new String[1];
            List<Integer> starts = new ArrayList<>();
            List<List<String>> rows = parseCsv(decode(raw, enc), ',', starts, null);
            if (rows.isEmpty()) throw new IOException(p + ": empty rates file");
            Map<String, Integer> col = new HashMap<>();
            for (int i = 0; i < rows.get(0).size(); i++) col.put(rows.get(0).get(i).trim().toLowerCase(Locale.ROOT), i);
            for (String req : new String[]{"date", "currency", "rate"})
                if (!col.containsKey(req)) throw new IOException(p + ": rates file needs columns date,currency,rate");
            int n = 0;
            Map<String, TreeMap<LocalDate, BigDecimal>> fresh = new TreeMap<>();
            for (int r = 1; r < rows.size(); r++) {
                List<String> f = rows.get(r);
                if (blankRow(f) || f.get(0).trim().startsWith("#")) continue;
                try {
                    LocalDate d = LocalDate.parse(f.get(col.get("date")).trim());
                    String c = f.get(col.get("currency")).trim().toUpperCase(Locale.ROOT);
                    BigDecimal rate = new BigDecimal(f.get(col.get("rate")).trim());
                    if (rate.signum() <= 0) throw new IllegalArgumentException("rate must be positive");
                    fresh.computeIfAbsent(c, k -> new TreeMap<>()).put(d, rate);
                    n++;
                } catch (Exception e) {
                    throw new IOException(p.getFileName() + ":" + starts.get(r) + ": " + e.getMessage());
                }
            }
            for (Map.Entry<String, TreeMap<LocalDate, BigDecimal>> e : fresh.entrySet())
                rates.computeIfAbsent(e.getKey(), k -> new TreeMap<>()).putAll(e.getValue());
            ratesInfo = "Rates: " + p.getFileName() + " sha256 " + sha256(raw) + "  (" + n + " rates for " + fresh.keySet()
                    + "; 1 unit = rate x " + s.base + ")";
            reconvert();
            audit("rates loaded from " + p + " sha256=" + sha256(raw));
        }

        void loadWatchlist(Path p) throws Exception {
            byte[] raw = Files.readAllBytes(p);
            String[] enc = new String[1];
            List<Integer> starts = new ArrayList<>();
            List<List<String>> rows = parseCsv(decode(raw, enc), ',', starts, null);
            int n = 0;
            for (int r = 0; r < rows.size(); r++) {
                List<String> f = rows.get(r);
                if (blankRow(f) || f.get(0).trim().startsWith("#")) continue;
                String type = f.get(0).trim().toLowerCase(Locale.ROOT);
                if (r == 0 && type.equals("type")) continue;
                if (!Set.of("account", "ip", "device").contains(type) || f.size() < 2 || f.get(1).trim().isEmpty())
                    throw new IOException(p.getFileName() + ":" + starts.get(r) + ": expected  account|ip|device , value [, note]");
                watch.put(type + ":" + f.get(1).trim(), f.size() > 2 ? f.get(2).trim() : "");
                n++;
            }
            watchInfo = "Watchlist: " + p.getFileName() + " sha256 " + sha256(raw) + "  (" + n + " entries)";
            cache = null;
            audit("watchlist loaded from " + p + " sha256=" + sha256(raw));
        }

        // -----------------------------------------------------------------
        // Summary and data warnings
        // -----------------------------------------------------------------
        List<String> dataWarnings() {
            List<String> w = new ArrayList<>();
            for (Source x : sources) {
                if (x.zoneless > 0 && !x.explicitZone)
                    w.add(x.name + ": " + x.zoneless + " timestamp(s) have no time zone and were read as UTC. UK bank exports are"
                            + " usually in UK local time - if so, reload with --tz Europe/London (or tz= in a mapping file).");
                if (x.zoneless > 0 && x.zoned > 0)
                    w.add(x.name + ": mixes " + x.zoned + " timestamps with a zone and " + x.zoneless + " without - check the export.");
            }
            Map<String, Integer> unconv = new TreeMap<>();
            int later = 0;
            for (Tx t : txs) {
                if (!t.converted) unconv.merge(t.cur(s.base), 1, Integer::sum);
                if (t.laterRate) later++;
            }
            for (Map.Entry<String, Integer> e : unconv.entrySet())
                w.add(e.getValue() + " transaction(s) in " + e.getKey() + " could not be converted to " + s.base
                        + " (no rate loaded) - totals and detectors mix currencies. Use: rates <rates.csv>");
            if (later > 0)
                w.add(later + " conversion(s) used the earliest rate AFTER the payment date (no earlier rate in the rates file).");
            if (!skipped.isEmpty()) w.add(skipped.size() + " row(s) could not be loaded - see 'skipped'.");
            w.addAll(warnings);
            return w;
        }

        void summary() {
            out.println("== CASE DATA SUMMARY ==");
            out.println("Sherlock     : " + VERSION);
            out.println("Source files : " + sources.size());
            for (int i = 0; i < sources.size(); i++) {
                Source x = sources.get(i);
                out.println(String.format("  [%d] %s", i + 1, x.name));
                out.println("      SHA-256  " + x.hash + "   (record this for continuity of evidence)");
                out.println("      " + x.mapping + ", " + x.encoding + ", times read as " + x.zone + ", rows " + x.rows + ": "
                        + x.loaded + " loaded, " + x.merged + " merged as duplicates, " + x.skipped + " skipped");
            }
            if (ratesInfo != null) out.println(ratesInfo);
            if (watchInfo != null) out.println(watchInfo);
            out.println("Transactions : " + txs.size() + (merges.isEmpty() ? "" : "  (" + merges.size() + " cross-file duplicates merged - see 'dupes')"));
            out.println("Accounts     : " + accounts().size());
            if (!txs.isEmpty()) {
                out.println("Period       : " + ts(txs.get(0).time) + "  to  " + ts(txs.get(txs.size() - 1).time) + "  (times shown in " + s.tz + ")");
                out.println("Total value  : " + money(sum(txs)) + " " + s.base);
            }
            out.println("Tracing rule : " + s.traceMode);
            List<String> w = dataWarnings();
            for (String x : w) out.println("WARNING      : " + x);
            int show = full ? skipped.size() : Math.min(10, skipped.size());
            for (int i = 0; i < show; i++) out.println("SKIPPED      : " + skipped.get(i));
            if (skipped.size() > show) out.println("SKIPPED      : ... and " + (skipped.size() - show) + " more - type 'skipped' to list all.");
        }

        void listSkipped() {
            out.println("== ROWS NOT LOADED (" + skipped.size() + ") ==");
            if (skipped.isEmpty()) out.println("None.");
            skipped.forEach(out::println);
        }

        void listMerges() {
            out.println("== CROSS-FILE DUPLICATES MERGED (" + merges.size() + ") ==");
            if (merges.isEmpty()) out.println("None." + (s.dedupe ? "" : "  (de-duplication is switched off)"));
            merges.forEach(out::println);
        }

        // -----------------------------------------------------------------
        // Detectors
        // -----------------------------------------------------------------
        List<Detector> buildDetectors() {
            List<Detector> d = new ArrayList<>();
            d.add(new Detector("shared-device", "SHARED_DEVICE", "accounts that send money from the same device",
                    (fs, n) -> detectShared(fs, true)));
            d.add(new Detector("shared-ip", "SHARED_IP", "accounts that send money from the same IP (weaker)",
                    (fs, n) -> detectShared(fs, false)));
            d.add(new Detector("structuring", "STRUCTURING", "repeated payments just under a threshold, in or out",
                    (fs, n) -> detectStructuring(fs)));
            d.add(new Detector("pass-through", "PASS_THROUGH", "money forwarded on almost as soon as it arrives (mule)",
                    (fs, n) -> detectPassThrough(fs)));
            d.add(new Detector("fan-in", "FAN_IN", "many different senders in a short window (collection account)",
                    (fs, n) -> detectFan(fs, true)));
            d.add(new Detector("fan-out", "FAN_OUT", "many different recipients in a short window (dispersal)",
                    (fs, n) -> detectFan(fs, false)));
            d.add(new Detector("cycles", "CIRCULAR_FLOW, ROUND_TRIP", "money moving in a loop, hop after hop in time order",
                    this::detectCycles));
            d.add(new Detector("takeover", "ACCOUNT_TAKEOVER, ATO_PAYEE", "new device followed by an unusually large payment",
                    (fs, n) -> detectTakeover(fs)));
            d.add(new Detector("dormant", "DORMANT_REACTIVATED", "long silence, then a sudden burst of money",
                    (fs, n) -> detectDormant(fs)));
            d.add(new Detector("round-amounts", "ROUND_AMOUNTS", "most payments are exact round sums (weak)",
                    (fs, n) -> detectRound(fs)));
            d.add(new Detector("repeat-amounts", "REPEAT_AMOUNTS", "the same exact amount again and again (weak)",
                    (fs, n) -> detectRepeat(fs)));
            d.add(new Detector("watchlist", "WATCHLIST", "accounts, IPs or devices on the loaded watchlist",
                    (fs, n) -> detectWatchlist(fs)));
            d.add(new Detector("victims", "LIKELY_VICTIM, POSSIBLE_VICTIM", "safeguarding: payment patterns typical of scam victims",
                    (fs, n) -> detectVictims(fs)));
            return d;
        }

        List<Finding> findings() {
            if (cache != null) return cache;
            List<Finding> fs = new ArrayList<>();
            notes = new ArrayList<>();
            for (Detector d : detectors) if (!s.disabled.contains(d.name)) d.fn.run(fs, notes);
            cache = fs;
            return fs;
        }

        void listDetectors() {
            out.println("== DETECTORS ==");
            for (Detector d : detectors)
                out.println(String.format("  %-15s %-9s %-30s %s", d.name, s.disabled.contains(d.name) ? "OFF" : "on", d.types, d.description));
            out.println("Switch one off with 'disable <name>', back on with 'enable <name>'.");
        }

        Map<String, Map<String, List<Tx>>> senderMap(boolean device) {
            Map<String, Map<String, List<Tx>>> m = new TreeMap<>();
            for (Tx t : txs) {
                String key = device ? t.device : t.ip;
                if (!key.isEmpty()) m.computeIfAbsent(key, k -> new TreeMap<>()).computeIfAbsent(t.from, k -> new ArrayList<>()).add(t);
            }
            return m;
        }

        void detectShared(List<Finding> fs, boolean device) {
            int min = device ? s.deviceMin : s.ipMin;
            for (Map.Entry<String, Map<String, List<Tx>>> e : senderMap(device).entrySet()) {
                if (e.getValue().size() < min) continue;
                for (Map.Entry<String, List<Tx>> a : e.getValue().entrySet())
                    fs.add(new Finding(a.getKey(), device ? "SHARED_DEVICE" : "SHARED_IP", device ? 25 : 10, false,
                            (device ? "device " : "IP ") + e.getKey() + " also used by " + others(e.getValue().keySet(), a.getKey())
                                    + (device ? "" : " (weaker signal: shared Wi-Fi, VPN or mobile-network NAT)"), ids(a.getValue())));
            }
        }

        void detectStructuring(List<Finding> fs) {
            for (long thr : s.thresholds) {
                long lo = (long) Math.ceil(thr * s.structBand);
                for (int dir = 0; dir < 2; dir++) {
                    Map<String, List<Tx>> by = dir == 0 ? outBy : inBy;
                    for (Map.Entry<String, List<Tx>> e : by.entrySet()) {
                        List<Tx> band = e.getValue().stream().filter(t -> t.value >= lo && t.value < thr).collect(Collectors.toList());
                        int best = 0, bestStart = 0, j = 0;
                        for (int i = 0; i < band.size(); i++) {
                            while (secs(band.get(j).time, band.get(i).time) > s.structWindowHours * 3600L) j++;
                            if (i - j + 1 > best) { best = i - j + 1; bestStart = j; }
                        }
                        if (best < s.structMin) continue;
                        List<Tx> run = band.subList(bestStart, bestStart + best);
                        fs.add(new Finding(e.getKey(), "STRUCTURING", 25, false,
                                best + (dir == 0 ? " outgoing" : " incoming") + " payments just under " + money(thr) + " ("
                                        + money(lo) + " or more) within " + s.structWindowHours + "h, total " + money(sum(run))
                                        + ", from " + ts(run.get(0).time), ids(run)));
                    }
                }
            }
        }

        void detectPassThrough(List<Finding> fs) {
            for (String acct : accounts()) {
                List<Tx> ins = inBy.getOrDefault(acct, List.of()), outs = outBy.getOrDefault(acct, List.of());
                if (ins.isEmpty() || outs.isEmpty()) continue;
                long totIn = sum(ins);
                if (totIn < s.passMin) continue;
                ArrayDeque<long[]> q = new ArrayDeque<>();   // {remaining, arrival epoch seconds}
                int a = 0;
                long matched = 0;
                double weighted = 0;
                for (Tx o : outs) {
                    while (a < ins.size() && !ins.get(a).time.isAfter(o.time)) {
                        q.add(new long[]{ins.get(a).value, ins.get(a).time.getEpochSecond()});
                        a++;
                    }
                    long need = o.value;
                    while (need > 0 && !q.isEmpty()) {
                        long[] hd = q.peek();
                        long take = Math.min(hd[0], need);
                        hd[0] -= take; need -= take; matched += take;
                        weighted += (double) take * (o.time.getEpochSecond() - hd[1]);
                        if (hd[0] == 0) q.poll();
                    }
                }
                if (matched <= 0) continue;
                double avgHours = weighted / matched / 3600.0, ratio = (double) matched / totIn;
                if (ratio >= s.passRatio && avgHours <= s.dwellHours) {
                    List<Tx> both = new ArrayList<>(ins);
                    both.addAll(outs);
                    both.sort(Comparator.comparing((Tx t) -> t.time));
                    fs.add(new Finding(acct, "PASS_THROUGH", 30, false, String.format(Locale.ROOT,
                            "%.0f%% of %s received was forwarded on, held on average %.1f hours", ratio * 100, money(totIn), avgHours),
                            ids(both)));
                }
            }
        }

        void detectFan(List<Finding> fs, boolean incoming) {
            for (Map.Entry<String, List<Tx>> e : (incoming ? inBy : outBy).entrySet()) {
                List<Tx> l = e.getValue();
                Map<String, Integer> cnt = new HashMap<>();
                int j = 0, bestD = 0, bestJ = 0, bestI = -1;
                long total = 0, bestSum = 0;
                for (int i = 0; i < l.size(); i++) {
                    Tx t = l.get(i);
                    cnt.merge(incoming ? t.from : t.to, 1, Integer::sum);
                    total += t.value;
                    while (secs(l.get(j).time, t.time) > s.fanWindowDays * 86400L) {
                        Tx r = l.get(j);
                        String c = incoming ? r.from : r.to;
                        if (cnt.merge(c, -1, Integer::sum) == 0) cnt.remove(c);
                        total -= r.value;
                        j++;
                    }
                    if (cnt.size() > bestD) { bestD = cnt.size(); bestSum = total; bestJ = j; bestI = i; }
                }
                if (bestD >= s.fanMin)
                    fs.add(new Finding(e.getKey(), incoming ? "FAN_IN" : "FAN_OUT", 20, false,
                            bestD + " different " + (incoming ? "senders paid this account" : "recipients were paid") + " within "
                                    + s.fanWindowDays + " days (" + money(bestSum) + ")", ids(l.subList(bestJ, bestI + 1))));
            }
        }

        /** Loops where each hop happens after the previous one (and within cyclewindow): A->B->C->A. */
        void detectCycles(List<Finding> fs, List<String> notes) {
            Map<String, List<Tx>> found = new TreeMap<>();
            long[] budget = {500_000};
            boolean[] capped = {false};
            for (String start : new TreeSet<>(outBy.keySet())) {
                for (Tx t0 : outBy.get(start)) {
                    if (t0.to.equals(start) || t0.value < s.cycleMin) continue;
                    List<Tx> path = new ArrayList<>(List.of(t0));
                    cycleDfs(start, path, found, budget, capped);
                    if (capped[0]) break;
                }
                if (capped[0]) break;
            }
            if (capped[0])
                notes.add("Loop search stopped early (" + (found.size() >= 200 ? "200 loops found" : "search budget used up")
                        + ") - loop results are incomplete. Narrow it with 'set cyclewindow' or 'set cyclemin'.");
            for (Map.Entry<String, List<Tx>> e : found.entrySet()) {
                List<Tx> loop = e.getValue();
                List<String> accts = new ArrayList<>();
                for (Tx t : loop) accts.add(t.from);
                String path = String.join(" -> ", accts) + " -> " + accts.get(0);
                long secsTaken = secs(loop.get(0).time, loop.get(loop.size() - 1).time);
                boolean rt = loop.size() == 2;
                for (String a : accts)
                    fs.add(new Finding(a, rt ? "ROUND_TRIP" : "CIRCULAR_FLOW", rt ? 10 : 15, false,
                            (rt ? "money sent back again: " : "part of loop ") + path + ", completed in " + dur(secsTaken)
                                    + ", starting " + ts(loop.get(0).time), ids(loop)));
            }
        }

        void cycleDfs(String start, List<Tx> path, Map<String, List<Tx>> found, long[] budget, boolean[] capped) {
            if (capped[0]) return;
            Tx last = path.get(path.size() - 1);
            String cur = last.to;
            if (cur.equals(start)) {
                if (path.size() >= 2) {
                    List<String> accts = new ArrayList<>();
                    for (Tx t : path) accts.add(t.from);
                    int min = 0;
                    for (int i = 1; i < accts.size(); i++) if (accts.get(i).compareTo(accts.get(min)) < 0) min = i;
                    List<String> rot = new ArrayList<>(accts.subList(min, accts.size()));
                    rot.addAll(accts.subList(0, min));
                    String key = String.join("\u0001", rot);
                    List<Tx> prev = found.get(key);
                    if (prev == null || path.get(0).time.isBefore(prev.get(0).time)) {
                        if (prev == null && found.size() >= 200) { capped[0] = true; return; }
                        found.put(key, new ArrayList<>(path));
                    }
                }
                return;
            }
            if (path.size() >= s.cycleMaxLen) return;
            List<Tx> outs = outBy.get(cur);
            if (outs == null) return;
            int lo = 0, hi = outs.size();
            while (lo < hi) { int mid = (lo + hi) >>> 1; if (outs.get(mid).time.isBefore(last.time)) lo = mid + 1; else hi = mid; }
            for (int k = lo; k < outs.size(); k++) {
                Tx n = outs.get(k);
                if (secs(last.time, n.time) > s.cycleWindowHours * 3600L) break;
                if (--budget[0] <= 0) { capped[0] = true; return; }
                if (n == last || n.to.equals(cur) || n.value < s.cycleMin) continue;
                if (!n.to.equals(start)) {
                    boolean seen = false;
                    for (Tx t : path) if (t.from.equals(n.to)) { seen = true; break; }
                    if (seen) continue;
                }
                path.add(n);
                cycleDfs(start, path, found, budget, capped);
                path.remove(path.size() - 1);
                if (capped[0]) return;
            }
        }

        void detectTakeover(List<Finding> fs) {
            for (Map.Entry<String, List<Tx>> e : new TreeMap<>(outBy).entrySet()) {
                List<Tx> outs = e.getValue();
                Set<String> devs = new TreeSet<>(), ips = new TreeSet<>();
                List<Long> amts = new ArrayList<>();
                for (int i = 0; i < outs.size(); i++) {
                    Tx t = outs.get(i);
                    boolean newId = i >= s.atoHistory && (!t.device.isEmpty()
                            ? !devs.isEmpty() && !devs.contains(t.device)
                            : !t.ip.isEmpty() && !ips.isEmpty() && !ips.contains(t.ip));
                    if (newId) {
                        long med = median(amts);
                        Tx big = null;
                        for (int k = i; k < outs.size() && secs(t.time, outs.get(k).time) <= s.atoWindowHours * 3600L; k++)
                            if (med > 0 && outs.get(k).value >= s.atoFactor * med && outs.get(k).value >= s.passMin) { big = outs.get(k); break; }
                        if (big != null) {
                            String what = !t.device.isEmpty() ? "device " + t.device : "IP " + t.ip;
                            String usual = !t.device.isEmpty() ? devs.toString() : ips.toString();
                            String when = t == big ? "its very first payment" : "a payment " + dur(secs(t.time, big.time)) + " later";
                            fs.add(new Finding(e.getKey(), "ACCOUNT_TAKEOVER", 30, true, "new " + what + " first used " + ts(t.time)
                                    + " after " + i + " payments from " + usual + "; " + when + " sent " + money(big.value) + " to " + big.to
                                    + String.format(Locale.ROOT, " (%.0fx the usual median of ", (double) big.value / med) + money(med) + ")",
                                    ids(t == big ? List.of(t) : List.of(t, big))));
                            fs.add(new Finding(big.to, "ATO_PAYEE", 20, false, "received " + money(big.value) + " from " + e.getKey()
                                    + (t == big ? " in the first payment made from a new " + what
                                            : " " + dur(secs(t.time, big.time)) + " after a new " + what + " appeared")
                                    + " on the payer's account", List.of(big.id)));
                            break;
                        }
                    }
                    if (!t.device.isEmpty()) devs.add(t.device);
                    if (!t.ip.isEmpty()) ips.add(t.ip);
                    amts.add(t.value);
                }
            }
        }

        List<Tx> allOf(String acct) {
            List<Tx> all = new ArrayList<>(inBy.getOrDefault(acct, List.of()));
            for (Tx t : outBy.getOrDefault(acct, List.of())) if (!t.to.equals(acct)) all.add(t);
            all.sort(Comparator.comparing((Tx t) -> t.time).thenComparingInt(t -> t.line));
            return all;
        }

        void detectDormant(List<Finding> fs) {
            for (String acct : accounts()) {
                List<Tx> all = allOf(acct);
                List<Tx> bestBurst = null;
                long bestGap = 0, bestValue = 0;
                Tx bestPrev = null;
                for (int i = 1; i < all.size(); i++) {
                    long gap = secs(all.get(i - 1).time, all.get(i).time);
                    if (gap < s.dormantDays * 86400L) continue;
                    Instant st = all.get(i).time;
                    List<Tx> burst = new ArrayList<>();
                    long v = 0;
                    for (int k = i; k < all.size() && secs(st, all.get(k).time) <= s.burstDays * 86400L; k++) {
                        burst.add(all.get(k));
                        v += all.get(k).value;
                    }
                    if (burst.size() >= 2 && v >= s.passMin && v > bestValue) {
                        bestBurst = burst; bestGap = gap; bestValue = v; bestPrev = all.get(i - 1);
                    }
                }
                if (bestBurst != null)
                    fs.add(new Finding(acct, "DORMANT_REACTIVATED", 15, false, "inactive for " + bestGap / 86400 + " days (last activity "
                            + ts(bestPrev.time) + "), then " + bestBurst.size() + " transactions worth " + money(bestValue) + " within "
                            + s.burstDays + " days", ids(bestBurst)));
            }
        }

        void detectRound(List<Finding> fs) {
            BigDecimal unit = BigDecimal.valueOf(s.roundUnit).movePointLeft(2);
            for (String acct : accounts()) {
                // intermediaries only: victims are often told to pay round sums, which says nothing about them
                if (!inBy.containsKey(acct) || !outBy.containsKey(acct)) continue;
                List<Tx> all = allOf(acct);
                if (all.size() < s.roundMin || sum(all) < s.passMin) continue;
                List<Tx> round = all.stream().filter(t -> t.amount.remainder(unit).signum() == 0).collect(Collectors.toList());
                double ratio = (double) round.size() / all.size();
                if (round.size() >= s.roundMin && ratio >= s.roundRatio)
                    fs.add(new Finding(acct, "ROUND_AMOUNTS", 5, false, round.size() + " of " + all.size()
                            + " transactions are exact multiples of " + money(s.roundUnit) + " (weak signal on its own)", ids(round)));
            }
        }

        void detectRepeat(List<Finding> fs) {
            for (int dir = 0; dir < 2; dir++) {
                for (Map.Entry<String, List<Tx>> e : new TreeMap<>(dir == 0 ? outBy : inBy).entrySet()) {
                    Map<String, List<Tx>> groups = new TreeMap<>();
                    for (Tx t : e.getValue())
                        if (t.value >= s.repeatMinAmount)
                            groups.computeIfAbsent(t.amount.stripTrailingZeros().toPlainString() + " " + t.cur(s.base), k -> new ArrayList<>()).add(t);
                    List<Tx> best = null;
                    String bestKey = "";
                    for (Map.Entry<String, List<Tx>> g : groups.entrySet()) {
                        List<Tx> l = g.getValue();
                        int j = 0;
                        for (int i = 0; i < l.size(); i++) {
                            while (secs(l.get(j).time, l.get(i).time) > s.repeatWindowDays * 86400L) j++;
                            if (i - j + 1 >= s.repeatMin && (best == null || i - j + 1 > best.size())) {
                                best = new ArrayList<>(l.subList(j, i + 1));
                                bestKey = g.getKey();
                            }
                        }
                    }
                    if (best != null)
                        fs.add(new Finding(e.getKey(), "REPEAT_AMOUNTS", 5, false, best.size() + (dir == 0 ? " outgoing" : " incoming")
                                + " payments of exactly " + bestKey + " within " + s.repeatWindowDays + " days (weak signal on its own)", ids(best)));
                }
            }
        }

        void detectWatchlist(List<Finding> fs) {
            if (watch.isEmpty()) return;
            for (Map.Entry<String, String> w : watch.entrySet()) {
                String type = w.getKey().substring(0, w.getKey().indexOf(':')), value = w.getKey().substring(w.getKey().indexOf(':') + 1);
                String note = w.getValue().isEmpty() ? "" : " - " + w.getValue();
                if (type.equals("account")) {
                    if (accounts().contains(value))
                        fs.add(new Finding(value, "WATCHLIST", 40, false, "account is on the watchlist" + note, ids(allOf(value))));
                } else {
                    Map<String, List<Tx>> users = senderMap(type.equals("device")).get(value);
                    if (users != null)
                        for (Map.Entry<String, List<Tx>> u : users.entrySet())
                            fs.add(new Finding(u.getKey(), "WATCHLIST", 40, false, "sent money from watchlisted " + type + " " + value + note,
                                    ids(u.getValue())));
                }
            }
        }

        static final Set<String> COLLECTION_TYPES = Set.of("FAN_IN", "PASS_THROUGH", "STRUCTURING", "WATCHLIST", "SHARED_DEVICE",
                "CIRCULAR_FLOW", "ATO_PAYEE", "DORMANT_REACTIVATED");

        void detectVictims(List<Finding> fs) {
            Map<String, Set<String>> flagged = new HashMap<>();
            for (Finding f : fs) if (!f.safeguarding && COLLECTION_TYPES.contains(f.type))
                flagged.computeIfAbsent(f.account, k -> new TreeSet<>()).add(f.type);
            List<Pattern> kw = s.keywords.stream()
                    .map(k -> Pattern.compile("(?<![\\p{L}\\p{N}])" + Pattern.quote(k), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE))
                    .collect(Collectors.toList());
            for (Map.Entry<String, List<Tx>> e : new TreeMap<>(outBy).entrySet()) {
                String acct = e.getKey();
                Map<String, List<Tx>> byPayee = new TreeMap<>();
                for (Tx t : e.getValue()) if (!t.to.equals(acct)) byPayee.computeIfAbsent(t.to, k -> new ArrayList<>()).add(t);
                Finding best = null;
                for (Map.Entry<String, List<Tx>> pe : byPayee.entrySet()) {
                    List<Tx> l = pe.getValue();
                    int j = 0, n = 0, bj = 0, bi = 0;
                    for (int i = 0; i < l.size(); i++) {
                        while (secs(l.get(j).time, l.get(i).time) > s.victimWindowDays * 86400L) j++;
                        if (i - j + 1 > n) { n = i - j + 1; bj = j; bi = i; }
                    }
                    List<Tx> run = l.subList(bj, bi + 1);
                    long tot = sum(run);
                    Set<String> hits = new TreeSet<>();
                    for (Tx t : l) for (int k = 0; k < kw.size(); k++) if (kw.get(k).matcher(t.memo).find()) hits.add(s.keywords.get(k));
                    Set<String> pf = flagged.getOrDefault(pe.getKey(), Set.of());
                    String type = null;
                    if (n >= s.victimMin && tot >= s.passMin && (!hits.isEmpty() || !pf.isEmpty())) type = "LIKELY_VICTIM";
                    else if (!hits.isEmpty() && (!pf.isEmpty() || n >= s.victimMin)) type = "POSSIBLE_VICTIM";
                    if (type == null) continue;
                    Finding f = new Finding(acct, type, type.equals("LIKELY_VICTIM") ? 2 : 1, true,
                            n + " payment(s) totalling " + money(tot) + " to " + pe.getKey() + " within " + s.victimWindowDays + " days"
                                    + (hits.isEmpty() ? "" : "; memo keywords: " + String.join(", ", hits))
                                    + (pf.isEmpty() ? "" : "; payee flagged " + String.join(", ", pf)), ids(run));
                    if (best == null || f.weight > best.weight) best = f;
                    else if (f.weight == best.weight) fs.add(f);
                }
                if (best != null) fs.add(best);
            }
        }

        // -----------------------------------------------------------------
        // Ranking and analysis output
        // -----------------------------------------------------------------
        static int score(List<Finding> l) {
            Map<String, Integer> maxByType = new HashMap<>();
            for (Finding f : l) maxByType.merge(f.type, f.weight, Math::max);
            int t = 0;
            for (int v : maxByType.values()) t += v;
            return t;
        }

        static String level(int sc) { return sc >= 60 ? "HIGH" : sc >= 30 ? "MEDIUM" : "LOW"; }

        List<Ranked> rank(boolean safeguarding) {
            Map<String, Ranked> by = new TreeMap<>();
            for (Finding f : findings())
                if (f.safeguarding == safeguarding) by.computeIfAbsent(f.account, Ranked::new).findings.add(f);
            List<Ranked> r = new ArrayList<>(by.values());
            for (Ranked x : r) {
                x.score = score(x.findings);
                x.in = sum(inBy.getOrDefault(x.account, List.of()));
                x.out = sum(outBy.getOrDefault(x.account, List.of()));
            }
            r.sort((x, y) -> {
                int c = Integer.compare(y.score, x.score);
                return c != 0 ? c : x.account.compareTo(y.account);
            });
            return r;
        }

        List<Ranked> ranking() { return rank(false); }
        List<Ranked> safeguarding() { return rank(true); }

        Map<String, Ranked> rankingMap() {
            Map<String, Ranked> m = new HashMap<>();
            for (Ranked r : ranking()) m.put(r.account, r);
            return m;
        }

        void printFinding(Finding f) {
            out.println("    - " + f.type + ": " + f.detail);
            if (!f.txIds.isEmpty()) out.println("        tx: " + fmtIds(f.txIds));
        }

        void analyze(boolean all) {
            List<Ranked> r = ranking();
            out.println("== SUSPICION RANKING ==   (score = highest weight of each finding type, added up)");
            if (r.isEmpty()) out.println("No patterns matched the current thresholds (see 'settings').");
            int limit = all || full ? r.size() : Math.min(25, r.size());
            for (int i = 0; i < limit; i++) {
                Ranked x = r.get(i);
                out.println();
                out.println(String.format("%-22s score %3d  [%s]  in %s / out %s", x.account, x.score, level(x.score), money(x.in), money(x.out)));
                for (Finding f : x.findings) printFinding(f);
            }
            if (r.size() > limit) out.println("\n... " + (r.size() - limit) + " lower-scoring accounts not shown ('analyze all' lists them).");
            out.println();
            printSafeguarding();
            if (!notes.isEmpty()) { out.println("\n== NOTES =="); notes.forEach(n -> out.println("  " + n)); }
            out.println("\nScores are a triage aid only. Legitimate activity (businesses, charities, shared households) can match"
                    + " these patterns. Verify with source records.");
        }

        void printSafeguarding() {
            List<Ranked> v = safeguarding();
            out.println("== SAFEGUARDING: POSSIBLE VICTIMS AND COMPROMISED ACCOUNTS ==");
            if (v.isEmpty()) { out.println("None identified with the current settings."); return; }
            v.sort((x, y) -> {
                int c = Integer.compare(victimRank(y), victimRank(x));
                return c != 0 ? c : x.account.compareTo(y.account);
            });
            for (Ranked x : v) {
                out.println();
                out.println(String.format("%-22s [%s]  sent %s", x.account,
                        x.findings.stream().map(f -> f.type).distinct().collect(Collectors.joining(", ")), money(x.out)));
                for (Finding f : x.findings) printFinding(f);
            }
            out.println("\nThese accounts may belong to victims: consider safeguarding contact before any enforcement action.");
        }

        static int victimRank(Ranked r) {
            int m = 0;
            for (Finding f : r.findings) m = Math.max(m, f.type.equals("LIKELY_VICTIM") || f.type.equals("ACCOUNT_TAKEOVER") ? 2 : 1);
            return m;
        }

        void findingsOfType(String type) {
            String t = type.toUpperCase(Locale.ROOT);
            List<Finding> l = findings().stream().filter(f -> f.type.equals(t)).collect(Collectors.toList());
            Set<String> known = new TreeSet<>();
            for (Detector d : detectors) for (String x : d.types.split(",\\s*")) known.add(x);
            if (!known.contains(t)) throw new IllegalArgumentException("unknown finding type '" + type + "'. Types: " + String.join(", ", known));
            out.println("== FINDINGS: " + t + " (" + l.size() + ") ==");
            for (Finding f : l) {
                out.println(f.account);
                printFinding(f);
            }
        }

        // -----------------------------------------------------------------
        // Clusters
        // -----------------------------------------------------------------
        List<Cluster> clusters() {
            Map<String, Map<String, List<Tx>>> byDev = senderMap(true), byIp = senderMap(false);
            Map<String, String> parent = new HashMap<>();
            for (Map<String, List<Tx>> g : byDev.values()) if (g.size() >= s.deviceMin) union(parent, g.keySet());
            for (Map<String, List<Tx>> g : byIp.values()) if (g.size() >= s.ipMin) union(parent, g.keySet());
            Map<String, Cluster> cl = new TreeMap<>();
            for (String a : new ArrayList<>(parent.keySet())) cl.computeIfAbsent(find(parent, a), k -> new Cluster()).members.add(a);
            List<Cluster> r = new ArrayList<>(cl.values());
            for (Cluster c : r) {
                for (Map.Entry<String, Map<String, List<Tx>>> e : byDev.entrySet())
                    if (e.getValue().size() >= s.deviceMin && c.members.containsAll(e.getValue().keySet()))
                        c.reasons.add("device " + e.getKey() + " used by " + e.getValue().keySet());
                for (Map.Entry<String, Map<String, List<Tx>>> e : byIp.entrySet())
                    if (e.getValue().size() >= s.ipMin && c.members.containsAll(e.getValue().keySet()))
                        c.reasons.add("IP " + e.getKey() + " used by " + e.getValue().keySet());
                for (String m : c.members) { c.in += sum(inBy.getOrDefault(m, List.of())); c.out += sum(outBy.getOrDefault(m, List.of())); }
            }
            r.sort((x, y) -> Integer.compare(y.members.size(), x.members.size()));
            return r;
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

        void links() {
            out.println("== LINKED ACCOUNT CLUSTERS (shared device / IP) ==");
            List<Cluster> cl = clusters();
            if (cl.isEmpty()) { out.println("None found."); return; }
            int n = 1;
            for (Cluster c : cl) {
                out.println("\nCluster " + n++ + ": " + c.members);
                for (String r : c.reasons) out.println("    " + r);
                out.println("    combined received " + money(c.in) + ", combined sent " + money(c.out));
            }
        }

        // -----------------------------------------------------------------
        // Tracing
        // -----------------------------------------------------------------
        Map<Tx, String> seedsFor(List<String> victims, Instant since) {
            Map<Tx, String> seeds = new IdentityHashMap<>();
            for (String v : victims)
                for (Tx t : outBy.getOrDefault(v, List.of()))
                    if (!t.to.equals(v) && (since == null || !t.time.isBefore(since))) seeds.put(t, v);
            return seeds;
        }

        /**
         * Replays every transaction in time order. Each account is a pool of labelled money; a payment takes money out of the
         * sender's pool according to the tracing rule. Seed payments turn their untraced money into the victim's label.
         * In origin mode (originTarget != null) money that an account pays out without having received it is labelled with that
         * account, which answers "where did the money that reached the target originally come from?".
         */
        Trace runTrace(Map<Tx, String> seeds, String mode, String originTarget) {
            Trace t = new Trace();
            t.mode = mode;
            boolean origin = originTarget != null;
            for (Tx x : txs) {
                Pool from = t.pools.computeIfAbsent(x.from, k -> new Pool(mode));
                Pool to = t.pools.computeIfAbsent(x.to, k -> new Pool(mode));
                TreeMap<String, Long> parts = from.withdraw(x.value);
                long got = total(parts);
                if (got < x.value) parts.merge(origin ? x.from : CLEAN, x.value - got, Long::sum);
                String seed = origin ? null : seeds.get(x);
                if (seed != null) {
                    Long fresh = parts.remove(CLEAN);
                    if (fresh != null && fresh > 0) { parts.merge(seed, fresh, Long::sum); t.seeded.merge(seed, fresh, Long::sum); }
                    t.seedCount.merge(seed, 1, Integer::sum);
                }
                to.deposit(parts);
                if (origin) {
                    if (x.to.equals(originTarget) && !x.from.equals(originTarget)) {
                        for (Map.Entry<String, Long> e : parts.entrySet()) t.intoTarget.merge(e.getKey(), e.getValue(), Long::sum);
                        t.targetReceived += x.value;
                        t.targetPayments++;
                    }
                    continue;
                }
                TreeMap<String, Long> traced = new TreeMap<>(parts);
                traced.remove(CLEAN);
                if (!traced.isEmpty()) t.steps.add(new Step(x, traced));
            }
            return t;
        }

        String status(Trace t, String acct) {
            if (t.seeded.containsKey(acct)) return "returned to a victim account";
            if (!outBy.containsKey(acct)) return "EXIT: no onward payments in data - priority for freezing / production orders";
            return "held at end of data, or moved by a route not in this data";
        }

        List<Map.Entry<String, TreeMap<String, Long>>> heldSorted(Trace t) {
            List<Map.Entry<String, TreeMap<String, Long>>> rows = new ArrayList<>(t.held().entrySet());
            rows.sort((x, y) -> {
                int c = Long.compare(total(y.getValue()), total(x.getValue()));
                return c != 0 ? c : x.getKey().compareTo(y.getKey());
            });
            return rows;
        }

        void printTrace(Trace t) {
            out.println("== MONEY TRAIL ==");
            out.println("Starting from : " + t.label);
            out.println("Tracing rule  : " + t.mode + " - " + MODE_TEXT.get(t.mode));
            out.println("Times shown in: " + s.tz);
            out.println("Seeded        : " + money(t.seededTotal()) + " " + s.base + " across " + t.seedPayments() + " payment(s)");
            if (t.seeded.size() > 1)
                for (Map.Entry<String, Long> e : t.seeded.entrySet())
                    out.println(String.format("                %-22s %14s", e.getKey(), money(e.getValue())));
            if (t.seededTotal() == 0) { out.println("No traceable money in the starting payments."); return; }
            out.println();
            for (Step st : t.steps) {
                Tx x = st.tx;
                String brk = st.parts.size() > 1 ? "  [" + st.parts.entrySet().stream().map(e -> e.getKey() + " " + money(e.getValue()))
                        .collect(Collectors.joining("; ")) + "]" : "";
                out.println(String.format("%s  %-8s %-18s -> %-18s %12s of %12s%s  ip=%s dev=%s%s  (%s)", ts(x.time), x.id, x.from, x.to,
                        money(total(st.parts)), money(x.value), brk, dash(x.ip), dash(x.device),
                        x.memo.isEmpty() ? "" : "  \"" + oneLine(x.memo) + "\"", x.ref()));
            }
            out.println("\n== WHERE THE TRACED MONEY IS AT THE END OF THE DATA ==");
            List<Map.Entry<String, TreeMap<String, Long>>> rows = heldSorted(t);
            long seeded = t.seededTotal(), located = 0;
            if (rows.isEmpty()) out.println("Nothing traceable remains.");
            for (Map.Entry<String, TreeMap<String, Long>> r : rows) {
                long tot = total(r.getValue());
                located += tot;
                out.println(String.format(Locale.ROOT, "%-22s %14s  (%5.1f%%)  %s", r.getKey(), money(tot), pct(tot, seeded), status(t, r.getKey())));
            }
            if (t.seeded.size() > 1) printAttribution(t, rows);
            out.println("\nReconciliation: " + money(located) + " located = " + money(seeded) + " seeded"
                    + (located == seeded ? "  (OK)" : "  (MISMATCH - please report this)"));
            out.println("Method: " + t.mode + " - " + MODE_TEXT.get(t.mode) + " The legal rules for tracing mixed funds differ:"
                    + " confirm the approach with the prosecutor. 'compare' shows how the choice of rule changes the result.");
        }

        void printAttribution(Trace t, List<Map.Entry<String, TreeMap<String, Long>>> rows) {
            List<String> vs = new ArrayList<>(t.seeded.keySet());
            out.println("\n== ATTRIBUTION BY VICTIM ==");
            StringBuilder hd = new StringBuilder(String.format("%-22s", "Account"));
            for (String v : vs) hd.append(String.format(" %15s", clip(v, 15)));
            out.println(hd.append(String.format(" %15s", "Total")));
            for (Map.Entry<String, TreeMap<String, Long>> r : rows) {
                StringBuilder b = new StringBuilder(String.format("%-22s", clip(r.getKey(), 22)));
                for (String v : vs) b.append(String.format(" %15s", money(r.getValue().getOrDefault(v, 0L))));
                out.println(b.append(String.format(" %15s", money(total(r.getValue())))));
            }
            StringBuilder b = new StringBuilder(String.format("%-22s", "Seeded (lost)"));
            for (String v : vs) b.append(String.format(" %15s", money(t.seeded.get(v))));
            out.println(b.append(String.format(" %15s", money(t.seededTotal()))));
        }

        void compare(Map<Tx, String> seeds, String label) {
            Map<String, Map<String, Long>> byMode = new LinkedHashMap<>();
            Map<String, Long> seededBy = new LinkedHashMap<>();
            Trace any = null;
            for (String m : MODES) {
                Trace t = runTrace(seeds, m, null);
                any = t;
                seededBy.put(m, t.seededTotal());
                Map<String, Long> tot = new TreeMap<>();
                for (Map.Entry<String, TreeMap<String, Long>> e : t.held().entrySet()) tot.put(e.getKey(), total(e.getValue()));
                byMode.put(m, tot);
            }
            Map<String, Long> maxBy = new TreeMap<>();
            for (Map<String, Long> m : byMode.values()) for (Map.Entry<String, Long> e : m.entrySet()) maxBy.merge(e.getKey(), e.getValue(), Math::max);
            List<String> accts = new ArrayList<>(maxBy.keySet());
            accts.sort((x, y) -> {
                int c = Long.compare(maxBy.get(y), maxBy.get(x));
                return c != 0 ? c : x.compareTo(y);
            });
            out.println("== WHERE THE MONEY ENDS UP UNDER EACH TRACING RULE ==");
            out.println("Starting from: all payments out of " + label + "   (" + money(any == null ? 0 : any.seededTotal()) + " " + s.base + ")");
            StringBuilder hd = new StringBuilder(String.format("%-22s", "Account"));
            for (String m : MODES) hd.append(String.format(" %14s", m));
            out.println(hd.append("  status"));
            for (String a : accts) {
                StringBuilder b = new StringBuilder(String.format("%-22s", clip(a, 22)));
                for (String m : MODES) b.append(String.format(" %14s", money(byMode.get(m).getOrDefault(a, 0L))));
                out.println(b.append("  ").append(any == null ? "" : status(any, a)));
            }
            out.println();
            for (String m : MODES) out.println("  " + m + ": " + MODE_TEXT.get(m));
            out.println("Current rule for 'trace' and reports: " + s.traceMode + "   (change with: set tracemode <rule>)");
        }

        void reverse(String acct) {
            Trace t = runTrace(Map.of(), s.traceMode, acct);
            Map<String, Ranked> rk = rankingMap(), sg = new HashMap<>();
            for (Ranked r : safeguarding()) sg.put(r.account, r);
            out.println("== REVERSE TRACE: " + acct + " ==");
            out.println("Tracing rule : " + s.traceMode + (s.traceMode.equals("fifo") ? " - " + MODE_TEXT.get("fifo")
                    : " - in a reverse trace every pound carries an origin label, so this rule splits each payment pro rata"
                    + " (use 'set tracemode fifo' for first in, first out)"));
            out.println("Received     : " + money(t.targetReceived) + " " + s.base + " in " + t.targetPayments + " payment(s)");
            if (t.targetReceived == 0) return;
            Map<String, Long> direct = new TreeMap<>();
            for (Tx x : inBy.getOrDefault(acct, List.of())) if (!x.from.equals(acct)) direct.merge(x.from, x.value, Long::sum);
            out.println("\nPaid directly by:");
            direct.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                    .forEach(e -> out.println(String.format(Locale.ROOT, "  %-22s %14s  (%5.1f%%)%s", e.getKey(), money(e.getValue()),
                            pct(e.getValue(), t.targetReceived), tags(e.getKey(), rk, sg))));
            out.println("\nOriginally came from (the account that first put the money into this data):");
            t.intoTarget.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                    .forEach(e -> out.println(String.format(Locale.ROOT, "  %-22s %14s  (%5.1f%%)%s", e.getKey(), money(e.getValue()),
                            pct(e.getValue(), t.targetReceived), tags(e.getKey(), rk, sg))));
            out.println("\n'Originally came from' = the account paid this money out without having received it earlier in the data"
                    + " (for example a victim's own savings, or funds from outside the data set).");
        }

        String tags(String a, Map<String, Ranked> rk, Map<String, Ranked> sg) {
            List<String> t = new ArrayList<>();
            if (sg.containsKey(a)) t.add(sg.get(a).findings.stream().map(f -> f.type).distinct().collect(Collectors.joining("/")));
            if (rk.containsKey(a)) t.add(level(rk.get(a).score) + " " + rk.get(a).score);
            return t.isEmpty() ? "" : "  [" + String.join(", ", t) + "]";
        }

        // -----------------------------------------------------------------
        // Timeline and account profile
        // -----------------------------------------------------------------
        String amountText(Tx t) {
            return t.cur(s.base).equals(s.base) ? money(t.value) : t.amount.toPlainString() + " " + t.currency
                    + (t.converted ? " = " + money(t.value) : " (not converted)");
        }

        void timeline(String acct) {
            out.println("== TIMELINE: " + acct + " ==   (times in " + s.tz + ", amounts in " + s.base + ")");
            long net = 0;
            for (Tx t : txs) {
                boolean i = t.to.equals(acct), o = t.from.equals(acct);
                if (!i && !o) continue;
                if (i && o) { out.println(String.format("%s  %-8s %-3s (to itself) %s", ts(t.time), t.id, "=", amountText(t))); continue; }
                net += i ? t.value : -t.value;
                out.println(String.format("%s  %-8s %-3s %-18s %14s  net %14s  ip=%s dev=%s%s  (%s)", ts(t.time), t.id, i ? "IN" : "OUT",
                        i ? t.from : t.to, amountText(t), money(net), dash(t.ip), dash(t.device),
                        t.memo.isEmpty() ? "" : "  \"" + oneLine(t.memo) + "\"", t.ref()));
            }
            out.println("(net = total in minus total out within this data only, not the real balance)");
        }

        void account(String acct) {
            List<Tx> in = inBy.getOrDefault(acct, List.of()), o = outBy.getOrDefault(acct, List.of());
            out.println("== ACCOUNT: " + acct + " ==");
            out.println("Received : " + money(sum(in)) + " in " + in.size() + " payment(s) from "
                    + in.stream().map(t -> t.from).distinct().count() + " account(s)");
            out.println("Sent     : " + money(sum(o)) + " in " + o.size() + " payment(s) to "
                    + o.stream().map(t -> t.to).distinct().count() + " account(s)");
            List<Tx> all = allOf(acct);
            if (!all.isEmpty()) out.println("Active   : " + ts(all.get(0).time) + "  to  " + ts(all.get(all.size() - 1).time));
            out.println("Sources  : " + all.stream().map(t -> t.src).distinct().collect(Collectors.joining(", ")));
            out.println("IPs used (as sender)    : " + o.stream().map(t -> t.ip).filter(x -> !x.isEmpty()).collect(Collectors.toCollection(TreeSet::new)));
            out.println("Devices used (as sender): " + o.stream().map(t -> t.device).filter(x -> !x.isEmpty()).collect(Collectors.toCollection(TreeSet::new)));
            out.println("Top payers : " + top(in, true));
            out.println("Top payees : " + top(o, false));
            List<Finding> fs = findings().stream().filter(f -> f.account.equals(acct)).collect(Collectors.toList());
            List<Finding> sus = fs.stream().filter(f -> !f.safeguarding).collect(Collectors.toList());
            int sc = score(sus);
            out.println("Score      : " + (sus.isEmpty() ? "none" : sc + " [" + level(sc) + "]"));
            out.println("Findings   : " + (fs.isEmpty() ? "none" : ""));
            for (Finding f : fs) printFinding(f);
        }

        String top(List<Tx> l, boolean incoming) {
            Map<String, Long> m = new HashMap<>();
            for (Tx t : l) m.merge(incoming ? t.from : t.to, t.value, Long::sum);
            return m.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(5)
                    .map(e -> e.getKey() + " (" + money(e.getValue()) + ")").collect(Collectors.joining(", "));
        }

        // -----------------------------------------------------------------
        // Exports
        // -----------------------------------------------------------------
        void export(List<String> a) throws Exception {
            need(a, 3, "export dot|csv|tx <file> [victim...]");
            String kind = a.get(1).toLowerCase(Locale.ROOT);
            Path f = Paths.get(a.get(2));
            List<String> vs = new ArrayList<>();
            for (String x : a.subList(3, a.size())) vs.add(resolve(x));
            switch (kind) {
                case "dot":
                    writeOut(f, dot(edges(vs), vs));
                    out.println("Graphviz file written to " + f + "   (render with:  dot -Tsvg " + f + " -o graph.svg)");
                    break;
                case "csv": {
                    String prefix = a.get(2).replaceAll("\\.csv$", "");
                    Path ent = Paths.get(prefix + "-entities.csv"), lnk = Paths.get(prefix + "-links.csv");
                    Map<String, Edge> edges = edges(vs);
                    writeOut(ent, entitiesCsv(edges, vs));
                    writeOut(lnk, linksCsv(edges));
                    out.println("Wrote " + ent + " and " + lnk + "  (Gephi: import as nodes and edges tables; i2 ANB: import as entities and links)");
                    break;
                }
                case "tx":
                    writeOut(f, txCsv());
                    out.println("Wrote " + txs.size() + " normalised transactions to " + f);
                    break;
                default:
                    throw new IllegalArgumentException("export dot|csv|tx <file> [victim...]");
            }
        }

        void writeOut(Path f, String content) throws Exception {
            byte[] b = content.getBytes(StandardCharsets.UTF_8);
            Files.write(f, b);
            audit("wrote " + f + " sha256=" + sha256(b));
        }

        Map<String, Edge> edges(List<String> victims) {
            Map<String, Edge> m = new LinkedHashMap<>();
            if (victims.isEmpty()) for (Tx t : txs) addEdge(m, t, t.value);
            else for (Step st : runTrace(seedsFor(victims, null), s.traceMode, null).steps) addEdge(m, st.tx, total(st.parts));
            return m;
        }

        static void addEdge(Map<String, Edge> m, Tx t, long v) {
            Edge e = m.computeIfAbsent(t.from + "\u0001" + t.to, k -> new Edge(t.from, t.to));
            e.total += v;
            e.count++;
            if (e.first == null || t.time.isBefore(e.first)) e.first = t.time;
            if (e.last == null || t.time.isAfter(e.last)) e.last = t.time;
            e.ids.add(t.id);
        }

        static String dq(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""; }

        String dot(Map<String, Edge> edges, List<String> victims) {
            Map<String, Ranked> rk = rankingMap();
            Set<String> sg = new HashSet<>();
            for (Ranked r : safeguarding()) sg.add(r.account);
            Set<String> nodes = new TreeSet<>();
            long max = 1;
            for (Edge e : edges.values()) { nodes.add(e.from); nodes.add(e.to); max = Math.max(max, e.total); }
            StringBuilder b = new StringBuilder("digraph sherlock {\n  rankdir=LR;\n");
            b.append("  graph [fontname=\"Helvetica\", labelloc=t, label=").append(dq("Sherlock " + VERSION + " - "
                    + (victims.isEmpty() ? "all transactions" : "money traced from " + String.join(", ", victims) + " (" + s.traceMode + ")")))
                    .append("];\n");
            b.append("  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", fontsize=10, fillcolor=\"#eeeeee\"];\n");
            b.append("  edge [fontname=\"Helvetica\", fontsize=9, color=\"#5d6d7e\"];\n");
            for (String n : nodes) {
                Ranked r = rk.get(n);
                boolean exit = !outBy.containsKey(n);
                String fill = victims.contains(n) || sg.contains(n) ? "#a9dfbf" : r == null ? "#eeeeee"
                        : r.score >= 60 ? "#f5b7b1" : r.score >= 30 ? "#fad7a0" : "#fcf3cf";
                String label = n + (r == null ? "" : "\nscore " + r.score + " " + level(r.score)) + (sg.contains(n) ? "\npossible victim" : "")
                        + (exit ? "\nEXIT" : "");
                b.append("  ").append(dq(n)).append(" [label=").append(dq(label)).append(", fillcolor=\"").append(fill).append("\"")
                        .append(exit ? ", peripheries=2" : "").append("];\n");
            }
            for (Edge e : edges.values())
                b.append("  ").append(dq(e.from)).append(" -> ").append(dq(e.to)).append(" [label=")
                        .append(dq(money(e.total) + (e.count > 1 ? " (" + e.count + ")" : ""))).append(", penwidth=")
                        .append(String.format(Locale.ROOT, "%.2f", 1 + 5.0 * e.total / max)).append("];\n");
            return b.append("}\n").toString();
        }

        String entitiesCsv(Map<String, Edge> edges, List<String> victims) {
            Map<String, Ranked> rk = rankingMap(), sg = new HashMap<>();
            for (Ranked r : safeguarding()) sg.put(r.account, r);
            Set<String> nodes = new TreeSet<>();
            for (Edge e : edges.values()) { nodes.add(e.from); nodes.add(e.to); }
            StringBuilder b = new StringBuilder("Id,Label,Type,Score,Level,Received,Sent,Findings\n");
            for (String n : nodes) {
                Ranked r = rk.get(n);
                String type = victims.contains(n) || sg.containsKey(n) ? "victim" : !outBy.containsKey(n) ? "exit" : "account";
                List<String> types = new ArrayList<>();
                if (r != null) r.findings.stream().map(f -> f.type).distinct().forEach(types::add);
                if (sg.containsKey(n)) sg.get(n).findings.stream().map(f -> f.type).distinct().forEach(types::add);
                b.append(csv(n)).append(',').append(csv(n)).append(',').append(type).append(',').append(r == null ? 0 : r.score).append(',')
                        .append(r == null ? "" : level(r.score)).append(',').append(plain(sum(inBy.getOrDefault(n, List.of())))).append(',')
                        .append(plain(sum(outBy.getOrDefault(n, List.of())))).append(',').append(csv(String.join(";", types))).append('\n');
            }
            return b.toString();
        }

        String linksCsv(Map<String, Edge> edges) {
            StringBuilder b = new StringBuilder("Source,Target,Weight,Count,First,Last,TxIds\n");
            for (Edge e : edges.values())
                b.append(csv(e.from)).append(',').append(csv(e.to)).append(',').append(plain(e.total)).append(',').append(e.count).append(',')
                        .append(e.first).append(',').append(e.last).append(',').append(csv(String.join(";", e.ids))).append('\n');
            return b.toString();
        }

        String txCsv() {
            StringBuilder b = new StringBuilder("id,timestamp_utc,from,to,amount,currency,value_" + s.base.toLowerCase(Locale.ROOT)
                    + ",converted,ip,device,memo,source,line,merged_from\n");
            for (Tx t : txs)
                b.append(csv(t.id)).append(',').append(t.time).append(',').append(csv(t.from)).append(',').append(csv(t.to)).append(',')
                        .append(t.amount.toPlainString()).append(',').append(t.cur(s.base)).append(',').append(plain(t.value)).append(',')
                        .append(t.converted).append(',').append(csv(t.ip)).append(',').append(csv(t.device)).append(',').append(csv(t.memo))
                        .append(',').append(csv(t.src)).append(',').append(t.line).append(',').append(csv(t.mergedFrom)).append('\n');
            return b.toString();
        }

        // -----------------------------------------------------------------
        // Reports
        // -----------------------------------------------------------------
        String capture(Action r) throws Exception {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            PrintStream old = out;
            out = new PrintStream(bos, true, StandardCharsets.UTF_8);
            try { r.run(); } finally { out.flush(); out = old; }
            return bos.toString(StandardCharsets.UTF_8);
        }

        void report(Path file, List<String> victims) throws Exception {
            String n = file.getFileName().toString().toLowerCase(Locale.ROOT);
            boolean wasFull = full;
            full = true;
            String content;
            try {
                content = n.endsWith(".html") || n.endsWith(".htm") ? htmlReport(victims) : capture(() -> textReport(victims));
            } finally { full = wasFull; }
            byte[] b = content.getBytes(StandardCharsets.UTF_8);
            Files.write(file, b);
            String hash = sha256(b);
            audit("report written to " + file + " sha256=" + hash);
            out.println("Report written to " + file.toAbsolutePath() + "\nSHA-256 " + hash);
        }

        List<String> stamp() {
            List<String> l = new ArrayList<>();
            l.add("Generated     : " + Instant.now().truncatedTo(ChronoUnit.SECONDS) + " (UTC)");
            l.add("Analyst       : " + (s.analyst.isEmpty() ? "(not set - use --analyst or 'set analyst')" : s.analyst));
            l.add("Tool          : Sherlock " + VERSION + ", Java " + System.getProperty("java.version"));
            l.add("Times shown in: " + s.tz);
            l.add("Base currency : " + s.base);
            l.add("Tracing rule  : " + s.traceMode);
            return l;
        }

        void textReport(List<String> victims) throws Exception {
            out.println("SHERLOCK CASE REPORT");
            out.println("====================");
            stamp().forEach(out::println);
            out.println();
            summary();
            out.println();
            printSettings();
            out.println();
            listMerges();
            out.println();
            analyze(true);
            out.println();
            links();
            if (!victims.isEmpty()) {
                out.println();
                Trace t = runTrace(seedsFor(victims, null), s.traceMode, null);
                t.label = "all payments out of " + String.join(", ", victims);
                printTrace(t);
            }
            out.println();
            out.println("== AUDIT LOG ==");
            audit.forEach(out::println);
            out.println("\nDISCLAIMER: automated analysis for investigative guidance only. Not evidence in itself. Every finding must be"
                    + " verified against original bank or provider records.");
        }

        static final String CSS = String.join("\n",
                ":root{--bg:#f5f4f0;--card:#ffffff;--ink:#1c2228;--muted:#5d6872;--line:#dcdfe3;--accent:#1f3a5f;--high:#b03a2e;"
                        + "--med:#b9770e;--low:#7b8a8b;--src:#1e8449;--exit:#b03a2e;--node:#5d6d7e;--flow:#2e86c1;--bar:#2e86c1;--chip:#eef1f4}",
                "@media (prefers-color-scheme:dark){:root{--bg:#121619;--card:#1b2126;--ink:#e6e9ec;--muted:#9aa5ae;--line:#2c343b;"
                        + "--accent:#9ec3e6;--node:#8a9bab;--flow:#5dade2;--bar:#5dade2;--chip:#242c33;--src:#52be80;--exit:#e74c3c}}",
                "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}",
                "main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}",
                "header{border-bottom:3px solid var(--accent);padding-bottom:16px;margin-bottom:8px}",
                ".eyebrow{margin:0;color:var(--muted);font-size:13px;letter-spacing:.06em;text-transform:uppercase}",
                "h1{margin:4px 0 12px;font-size:28px}h2{font-size:20px;margin:0 0 12px}",
                "section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px;margin-top:20px;overflow-x:auto}",
                ".meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:4px 24px;margin:0}",
                ".meta div{display:flex;gap:8px}.meta dt{color:var(--muted);min-width:110px}.meta dd{margin:0}",
                ".warn{background:var(--chip);border-left:4px solid var(--med);padding:8px 12px;border-radius:4px}",
                ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}",
                ".tile{border:1px solid var(--line);border-radius:8px;padding:10px 12px}.tile b{display:block;font-size:20px}.tile span{color:var(--muted);font-size:13px}",
                "table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}",
                "th{color:var(--muted);font-weight:600;font-size:13px}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}",
                ".badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:700;color:#fff}",
                ".HIGH{background:var(--high)}.MEDIUM{background:var(--med)}.LOW{background:var(--low)}.VICTIM{background:var(--src)}",
                "ul.f{margin:0;padding-left:18px}ul.f li{margin-bottom:4px}.ids{color:var(--muted);font-size:12px;word-break:break-all}",
                "code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}pre{white-space:pre;overflow-x:auto;background:var(--chip);padding:12px;border-radius:6px}",
                "details summary{cursor:pointer;color:var(--accent);font-weight:600;margin:8px 0}",
                "svg text{fill:var(--ink);font-size:12px;paint-order:stroke;stroke:var(--card);stroke-width:3px;stroke-linejoin:round}svg .muted{fill:var(--muted)}",
                "td:first-child{white-space:nowrap}",
                ".legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin:8px 0}.sw{display:inline-block;width:12px;height:12px;border-radius:2px;margin-right:6px;vertical-align:-1px}",
                "footer{color:var(--muted);font-size:13px;margin-top:24px}");

        String htmlReport(List<String> victims) throws Exception {
            List<Ranked> rk = ranking(), sg = safeguarding();
            StringBuilder b = new StringBuilder(64_000);
            b.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
                    .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Sherlock case report</title><style>")
                    .append(CSS).append("</style></head><body><main>\n");
            b.append("<header><p class=\"eyebrow\">Sherlock ").append(VERSION).append(" &middot; case report</p><h1>Transaction analysis</h1><dl class=\"meta\">");
            for (String l : stamp()) {
                int i = l.indexOf(':');
                b.append("<div><dt>").append(h(l.substring(0, i).trim())).append("</dt><dd>").append(h(l.substring(i + 1).trim())).append("</dd></div>");
            }
            b.append("</dl><p class=\"warn\">Investigative leads only &ndash; not evidence in itself. Verify every finding against original bank or"
                    + " provider records.</p></header>\n");

            // Case data
            b.append("<section><h2>Case data</h2><div class=\"tiles\">");
            tile(b, String.valueOf(txs.size()), "transactions");
            tile(b, String.valueOf(accounts().size()), "accounts");
            tile(b, money(sum(txs)), "total value (" + s.base + ")");
            tile(b, String.valueOf(rk.stream().filter(r -> r.score >= 60).count()), "HIGH-scoring accounts");
            tile(b, String.valueOf(sg.size()), "possible victims / compromised");
            b.append("</div>");
            if (!txs.isEmpty())
                b.append("<p>Period ").append(h(ts(txs.get(0).time))).append(" to ").append(h(ts(txs.get(txs.size() - 1).time)))
                        .append(" (").append(h(s.tz.toString())).append(").</p>");
            b.append("<table><tr><th>Source file</th><th>SHA-256</th><th>Read as</th><th class=n>Rows</th><th class=n>Loaded</th>")
                    .append("<th class=n>Merged</th><th class=n>Skipped</th></tr>");
            for (Source x : sources)
                b.append("<tr><td>").append(h(x.name)).append("</td><td><code>").append(h(x.hash)).append("</code></td><td>").append(h(x.mapping))
                        .append(", ").append(h(x.encoding)).append(", ").append(h(x.zone)).append("</td><td class=n>").append(x.rows)
                        .append("</td><td class=n>").append(x.loaded).append("</td><td class=n>").append(x.merged).append("</td><td class=n>")
                        .append(x.skipped).append("</td></tr>");
            b.append("</table>");
            if (ratesInfo != null) b.append("<p>").append(h(ratesInfo)).append("</p>");
            if (watchInfo != null) b.append("<p>").append(h(watchInfo)).append("</p>");
            List<String> w = dataWarnings();
            if (!w.isEmpty()) {
                b.append("<h3>Warnings</h3><ul>");
                for (String x : w) b.append("<li>").append(h(x)).append("</li>");
                b.append("</ul>");
            }
            b.append("</section>\n");

            // Ranking
            b.append("<section><h2>Suspicion ranking</h2><p>Score = the highest weight of each finding type, added up. HIGH &ge; 60, MEDIUM &ge; 30.</p>");
            if (rk.isEmpty()) b.append("<p>No patterns matched the current thresholds.</p>");
            else {
                b.append("<table><tr><th>Account</th><th>Level</th><th class=n>Score</th><th class=n>Received</th><th class=n>Sent</th><th>Findings</th></tr>");
                for (Ranked r : rk) {
                    b.append("<tr><td><b>").append(h(r.account)).append("</b></td><td><span class=\"badge ").append(level(r.score)).append("\">")
                            .append(level(r.score)).append("</span></td><td class=n>").append(r.score).append("</td><td class=n>").append(money(r.in))
                            .append("</td><td class=n>").append(money(r.out)).append("</td><td>").append(findingList(r.findings)).append("</td></tr>");
                }
                b.append("</table>");
            }
            if (!notes.isEmpty()) for (String n : notes) b.append("<p class=\"warn\">").append(h(n)).append("</p>");
            b.append("</section>\n");

            // Safeguarding
            b.append("<section><h2>Safeguarding: possible victims and compromised accounts</h2>");
            if (sg.isEmpty()) b.append("<p>None identified with the current settings.</p>");
            else {
                b.append("<p>These accounts may belong to victims &ndash; consider safeguarding contact before any enforcement action.</p>")
                        .append("<table><tr><th>Account</th><th class=n>Sent</th><th>Findings</th></tr>");
                for (Ranked r : sg)
                    b.append("<tr><td><b>").append(h(r.account)).append("</b> <span class=\"badge VICTIM\">")
                            .append(h(r.findings.stream().map(f -> f.type).distinct().collect(Collectors.joining(", ")))).append("</span></td><td class=n>")
                            .append(money(r.out)).append("</td><td>").append(findingList(r.findings)).append("</td></tr>");
                b.append("</table>");
            }
            b.append("</section>\n");

            // Clusters
            List<Cluster> cl = clusters();
            b.append("<section><h2>Linked accounts</h2>");
            if (cl.isEmpty()) b.append("<p>No accounts share a device or IP above the thresholds.</p>");
            else {
                b.append("<table><tr><th>Cluster</th><th>Members</th><th>Linked by</th><th class=n>Received</th><th class=n>Sent</th></tr>");
                int n = 1;
                for (Cluster c : cl)
                    b.append("<tr><td>").append(n++).append("</td><td>").append(h(String.join(", ", c.members))).append("</td><td>")
                            .append(h(String.join("; ", c.reasons))).append("</td><td class=n>").append(money(c.in)).append("</td><td class=n>")
                            .append(money(c.out)).append("</td></tr>");
                b.append("</table>");
            }
            b.append("</section>\n");

            // Trace
            if (!victims.isEmpty()) {
                Trace t = runTrace(seedsFor(victims, null), s.traceMode, null);
                t.label = "all payments out of " + String.join(", ", victims);
                b.append("<section><h2>Money trail</h2><p>").append(h(money(t.seededTotal()))).append(" ").append(h(s.base))
                        .append(" traced from ").append(h(String.join(", ", victims))).append(" across ").append(t.seedPayments())
                        .append(" payment(s). Rule: <b>").append(h(t.mode)).append("</b> &ndash; ").append(h(MODE_TEXT.get(t.mode))).append("</p>");
                b.append("<div class=\"legend\"><span><i class=\"sw\" style=\"background:var(--src)\"></i>victim</span>")
                        .append("<span><i class=\"sw\" style=\"background:var(--node)\"></i>intermediate account</span>")
                        .append("<span><i class=\"sw\" style=\"background:var(--exit)\"></i>exit point (no onward payments)</span>")
                        .append("<span>dashed = money flowing back to an earlier account (loop)</span></div>");
                b.append(sankeySvg(t));
                b.append("<h3>Where the traced money is at the end of the data</h3><table><tr><th>Account</th>");
                List<String> vs = new ArrayList<>(t.seeded.keySet());
                if (vs.size() > 1) for (String v : vs) b.append("<th class=n>from ").append(h(v)).append("</th>");
                b.append("<th class=n>Traced</th><th class=n>Share</th><th>Status</th></tr>");
                for (Map.Entry<String, TreeMap<String, Long>> r : heldSorted(t)) {
                    long tot = total(r.getValue());
                    b.append("<tr><td>").append(h(r.getKey())).append("</td>");
                    if (vs.size() > 1) for (String v : vs) b.append("<td class=n>").append(money(r.getValue().getOrDefault(v, 0L))).append("</td>");
                    b.append("<td class=n><b>").append(money(tot)).append("</b></td><td class=n>")
                            .append(String.format(Locale.ROOT, "%.1f%%", pct(tot, t.seededTotal()))).append("</td><td>").append(h(status(t, r.getKey())))
                            .append("</td></tr>");
                }
                b.append("</table>");
                Trace tt = t;
                b.append("<details><summary>Every traced payment, in time order</summary><pre>").append(h(capture(() -> printTrace(tt))))
                        .append("</pre></details>");
                b.append("<details><summary>How the result changes with the tracing rule</summary><pre>")
                        .append(h(capture(() -> compare(seedsFor(victims, null), String.join(", ", victims))))).append("</pre></details>");
                b.append("</section>\n");
            }

            // Charts
            Set<String> flagged = new HashSet<>();
            for (Ranked r : rk) if (r.score >= 30) flagged.add(r.account);
            b.append("<section><h2>Activity</h2><p>Value moved by HIGH and MEDIUM accounts (in or out), per ")
                    .append(chartWeekly() ? "week" : "day").append(".</p>").append(activitySvg(flagged));
            List<String> lossFor = new ArrayList<>(victims);
            if (lossFor.isEmpty()) for (Ranked r : sg) if (victimRank(r) == 2 && lossFor.size() < 6) lossFor.add(r.account);
            if (!lossFor.isEmpty()) b.append("<h3>Cumulative payments out of victim accounts</h3>").append(lossSvg(lossFor));
            b.append("</section>\n");

            // Settings, skipped, merges, audit
            b.append("<section><h2>Settings used</h2><table><tr><th>Setting</th><th>Value</th><th>Meaning</th></tr>");
            for (Param p : params.values())
                b.append("<tr><td><code>").append(h(p.name)).append("</code></td><td>").append(h(p.get.get())).append("</td><td>")
                        .append(h(p.help)).append("</td></tr>");
            b.append("<tr><td><code>disabled</code></td><td>").append(h(s.disabled.isEmpty() ? "none" : String.join(", ", s.disabled)))
                    .append("</td><td>detectors switched off</td></tr></table></section>\n");
            b.append("<section><h2>Data handling records</h2>");
            b.append("<details><summary>Rows not loaded (").append(skipped.size()).append(")</summary><pre>")
                    .append(h(skipped.isEmpty() ? "None." : String.join("\n", skipped))).append("</pre></details>");
            b.append("<details><summary>Cross-file duplicates merged (").append(merges.size()).append(")</summary><pre>")
                    .append(h(merges.isEmpty() ? "None." : String.join("\n", merges))).append("</pre></details>");
            b.append("<details><summary>Audit log (").append(audit.size()).append(" entries)</summary><pre>").append(h(String.join("\n", audit)))
                    .append("</pre></details></section>\n");
            b.append("<footer>Automated analysis for investigative guidance only. Not evidence in itself. Generated by Sherlock ")
                    .append(VERSION).append(".</footer></main></body></html>\n");
            return b.toString();
        }

        static void tile(StringBuilder b, String v, String label) {
            b.append("<div class=\"tile\"><b>").append(h(v)).append("</b><span>").append(h(label)).append("</span></div>");
        }

        String findingList(List<Finding> fs) {
            StringBuilder b = new StringBuilder("<ul class=\"f\">");
            for (Finding f : fs)
                b.append("<li><b>").append(h(f.type)).append("</b>: ").append(h(f.detail))
                        .append(f.txIds.isEmpty() ? "" : "<div class=\"ids\">tx: " + h(String.join(", ", f.txIds)) + "</div>").append("</li>");
            return b.append("</ul>").toString();
        }

        /** Layered Sankey diagram of the traced money, drawn as inline SVG. */
        String sankeySvg(Trace t) {
            Map<String, Long> edge = new LinkedHashMap<>();
            for (Step st : t.steps) edge.merge(st.tx.from + "\u0001" + st.tx.to, total(st.parts), Long::sum);
            if (edge.isEmpty()) return "<p>No traced flows.</p>";
            Set<String> nodes = new LinkedHashSet<>();
            Map<String, List<String>> adj = new HashMap<>();
            Map<String, Long> inW = new HashMap<>(), outW = new HashMap<>();
            for (Map.Entry<String, Long> e : edge.entrySet()) {
                String[] p = e.getKey().split("\u0001", 2);
                nodes.add(p[0]);
                nodes.add(p[1]);
                adj.computeIfAbsent(p[0], k -> new ArrayList<>()).add(p[1]);
                outW.merge(p[0], e.getValue(), Long::sum);
                inW.merge(p[1], e.getValue(), Long::sum);
            }
            Map<String, Integer> depth = new HashMap<>();
            ArrayDeque<String> q = new ArrayDeque<>();
            for (String v : t.seeded.keySet()) if (nodes.contains(v)) { depth.put(v, 0); q.add(v); }
            while (!q.isEmpty()) {
                String u = q.poll();
                for (String v : adj.getOrDefault(u, List.of())) if (!depth.containsKey(v)) { depth.put(v, depth.get(u) + 1); q.add(v); }
            }
            for (String n : nodes) depth.putIfAbsent(n, 0);
            int maxD = 0;
            for (int d : depth.values()) maxD = Math.max(maxD, d);
            Map<String, Long> wt = new HashMap<>();
            for (String n : nodes) wt.put(n, Math.max(inW.getOrDefault(n, 0L), outW.getOrDefault(n, 0L)));
            List<List<String>> layers = new ArrayList<>();
            for (int i = 0; i <= maxD; i++) layers.add(new ArrayList<>());
            for (String n : nodes) layers.get(depth.get(n)).add(n);
            long maxLayer = 1;
            int maxCount = 1;
            for (List<String> l : layers) {
                l.sort((a, c) -> { int x = Long.compare(wt.get(c), wt.get(a)); return x != 0 ? x : a.compareTo(c); });
                long sm = 0;
                for (String n : l) sm += wt.get(n);
                maxLayer = Math.max(maxLayer, sm);
                maxCount = Math.max(maxCount, l.size());
            }
            double W = 1000, nodeW = 14, gap = 18, top = 20, avail = Math.max(260, 70.0 * maxCount);
            double scale = Math.max(1e-9, (avail - gap * (maxCount - 1)) / maxLayer);
            double colW = maxD == 0 ? 0 : (W - 40 - 220 - nodeW) / maxD;
            Map<String, double[]> pos = new HashMap<>();   // x, y, height
            double bottom = 0;
            for (int d = 0; d <= maxD; d++) {
                double y = top;
                for (String n : layers.get(d)) {
                    double hgt = Math.max(4, wt.get(n) * scale);
                    pos.put(n, new double[]{20 + d * colW, y, hgt});
                    y += hgt + gap;
                }
                bottom = Math.max(bottom, y);
            }
            double H = bottom + 60;
            StringBuilder b = new StringBuilder();
            b.append(String.format(Locale.ROOT, "<svg viewBox=\"0 0 %.0f %.0f\" width=\"100%%\" role=\"img\" aria-label=\"Sankey diagram of the traced money\">", W, H));
            b.append("<defs><marker id=\"sk-arrow\" viewBox=\"0 0 10 10\" refX=\"5\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\""
                    + " orient=\"auto-start-reverse\"><path d=\"M0 0L10 5L0 10z\" fill=\"var(--flow)\"/></marker></defs>");
            int backLane = 0;
            List<Map.Entry<String, Long>> es = new ArrayList<>(edge.entrySet());
            es.sort(Comparator.comparingDouble((Map.Entry<String, Long> e) -> pos.get(e.getKey().split("\u0001", 2)[0])[1])
                    .thenComparingDouble(e -> pos.get(e.getKey().split("\u0001", 2)[1])[1]));
            Map<String, Double> outOff = new HashMap<>(), inOff = new HashMap<>();
            for (Map.Entry<String, Long> e : es) {
                String[] p = e.getKey().split("\u0001", 2);
                double[] a = pos.get(p[0]), c = pos.get(p[1]);
                double w = Math.max(1, e.getValue() * scale);
                String tip = "<title>" + h(p[0] + " → " + p[1] + ": " + money(e.getValue()) + " " + s.base) + "</title>";
                if (depth.get(p[1]) > depth.get(p[0])) {
                    double y0 = a[1] + outOff.getOrDefault(p[0], 0.0), y1 = c[1] + inOff.getOrDefault(p[1], 0.0);
                    outOff.merge(p[0], w, Double::sum);
                    inOff.merge(p[1], w, Double::sum);
                    double x0 = a[0] + nodeW, x1 = c[0], xm = (x0 + x1) / 2;
                    b.append(String.format(Locale.ROOT, "<path d=\"M%.1f %.1fC%.1f %.1f %.1f %.1f %.1f %.1fL%.1f %.1fC%.1f %.1f %.1f %.1f %.1f %.1fZ\""
                                    + " fill=\"var(--flow)\" fill-opacity=\"0.35\">%s</path>",
                            x0, y0, xm, y0, xm, y1, x1, y1, x1, y1 + w, xm, y1 + w, xm, y0 + w, x0, y0 + w, tip));
                } else {
                    // money flowing back to an earlier (or the same) column: route it underneath everything
                    double x0 = a[0] + nodeW / 2, y0 = a[1] + a[2], xl = c[0] - 9, ye = c[1] + c[2] / 2;
                    double lane = bottom + 10 + 12 * (backLane++ % 3);
                    b.append(String.format(Locale.ROOT, "<path d=\"M%.1f %.1fV%.1fQ%.1f %.1f %.1f %.1fH%.1fQ%.1f %.1f %.1f %.1fV%.1fH%.1f\""
                                    + " fill=\"none\" stroke=\"var(--flow)\" stroke-width=\"%.1f\" stroke-dasharray=\"5 4\" stroke-opacity=\"0.8\""
                                    + " marker-end=\"url(#sk-arrow)\">%s</path>",
                            x0, y0, lane - 8, x0, lane, x0 - 8, lane, xl + 8, xl, lane, xl, lane - 8, ye, c[0] - 3,
                            Math.min(4, Math.max(1.5, w)), tip));
                }
            }
            for (String n : nodes) {
                double[] p = pos.get(n);
                boolean src = t.seeded.containsKey(n), exit = !outBy.containsKey(n);
                String fill = src ? "var(--src)" : exit ? "var(--exit)" : "var(--node)";
                long amt = src ? t.seeded.get(n) : inW.getOrDefault(n, 0L);
                b.append(String.format(Locale.ROOT, "<rect x=\"%.1f\" y=\"%.1f\" width=\"%.0f\" height=\"%.1f\" rx=\"2\" fill=\"%s\"><title>%s</title></rect>",
                        p[0], p[1], nodeW, p[2], fill, h(n + ": " + money(amt))));
                b.append(String.format(Locale.ROOT, "<text x=\"%.1f\" y=\"%.1f\">%s</text><text class=\"muted\" x=\"%.1f\" y=\"%.1f\">%s</text>",
                        p[0] + nodeW + 6, p[1] + Math.min(p[2], 28) / 2 + 2, h(n), p[0] + nodeW + 6, p[1] + Math.min(p[2], 28) / 2 + 16,
                        h(money(amt) + (exit && !src ? "  exit" : ""))));
            }
            return b.append("</svg>").toString();
        }

        boolean chartWeekly() {
            if (txs.isEmpty()) return false;
            long days = ChronoUnit.DAYS.between(LocalDate.ofInstant(txs.get(0).time, s.tz), LocalDate.ofInstant(txs.get(txs.size() - 1).time, s.tz)) + 1;
            return days > 120;
        }

        String activitySvg(Set<String> flagged) {
            if (txs.isEmpty() || flagged.isEmpty()) return "<p>No HIGH or MEDIUM accounts.</p>";
            LocalDate d0 = LocalDate.ofInstant(txs.get(0).time, s.tz), d1 = LocalDate.ofInstant(txs.get(txs.size() - 1).time, s.tz);
            int step = chartWeekly() ? 7 : 1;
            int n = (int) ((ChronoUnit.DAYS.between(d0, d1) + step) / step);
            long[] bars = new long[n];
            for (Tx t : txs)
                if (flagged.contains(t.from) || flagged.contains(t.to))
                    bars[(int) (ChronoUnit.DAYS.between(d0, LocalDate.ofInstant(t.time, s.tz)) / step)] += t.value;
            long max = 1;
            for (long v : bars) max = Math.max(max, v);
            double W = 1000, H = 220, L = 90, B = 30, T = 10, cw = (W - L - 10) / n;
            StringBuilder b = new StringBuilder(String.format(Locale.ROOT,
                    "<svg viewBox=\"0 0 %.0f %.0f\" width=\"100%%\" role=\"img\" aria-label=\"Value moved by flagged accounts over time\">", W, H));
            b.append(String.format(Locale.ROOT, "<line x1=\"%.0f\" y1=\"%.0f\" x2=\"%.0f\" y2=\"%.0f\" stroke=\"var(--line)\"/>", L, H - B, W - 10, H - B));
            for (int i = 0; i < n; i++) {
                if (bars[i] == 0) continue;
                double hgt = (H - B - T) * bars[i] / max;
                LocalDate d = d0.plusDays((long) i * step);
                b.append(String.format(Locale.ROOT, "<rect x=\"%.1f\" y=\"%.1f\" width=\"%.1f\" height=\"%.1f\" fill=\"var(--bar)\" rx=\"1\"><title>%s</title></rect>",
                        L + i * cw + 1, H - B - hgt, Math.max(1, cw - 2), hgt, h((step == 7 ? "week of " : "") + d + ": " + money(bars[i]) + " " + s.base)));
            }
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\" text-anchor=\"end\">%s</text>", L - 6, T + 10, h(money(max))));
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\" text-anchor=\"end\">0</text>", L - 6, H - B));
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\">%s</text>", L, H - 8, h(d0.toString())));
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\" text-anchor=\"end\">%s</text>", W - 10, H - 8, h(d1.toString())));
            return b.append("</svg>").toString();
        }

        String lossSvg(List<String> victims) {
            String[] colors = {"var(--src)", "var(--flow)", "var(--med)", "var(--high)", "var(--node)", "var(--accent)"};
            List<Tx> all = new ArrayList<>();
            for (String v : victims) for (Tx t : outBy.getOrDefault(v, List.of())) if (!t.to.equals(v)) all.add(t);
            if (all.isEmpty()) return "<p>No payments out of these accounts.</p>";
            all.sort(Comparator.comparing((Tx t) -> t.time));
            long t0 = all.get(0).time.getEpochSecond(), t1 = Math.max(t0 + 86400, all.get(all.size() - 1).time.getEpochSecond());
            long max = 1;
            Map<String, Long> totals = new HashMap<>();
            for (Tx t : all) max = Math.max(max, totals.merge(t.from, t.value, Long::sum));
            double W = 1000, H = 220, L = 90, B = 30, T = 10;
            StringBuilder b = new StringBuilder(String.format(Locale.ROOT,
                    "<svg viewBox=\"0 0 %.0f %.0f\" width=\"100%%\" role=\"img\" aria-label=\"Cumulative payments out of victim accounts\">", W, H));
            b.append(String.format(Locale.ROOT, "<line x1=\"%.0f\" y1=\"%.0f\" x2=\"%.0f\" y2=\"%.0f\" stroke=\"var(--line)\"/>", L, H - B, W - 10, H - B));
            StringBuilder legend = new StringBuilder("<div class=\"legend\">");
            for (int vi = 0; vi < victims.size(); vi++) {
                String v = victims.get(vi), col = colors[vi % colors.length];
                StringBuilder pts = new StringBuilder();
                double px = L, py = H - B;
                pts.append(String.format(Locale.ROOT, "%.1f,%.1f", px, py));
                long cum = 0;
                for (Tx t : all) {
                    if (!t.from.equals(v)) continue;
                    double x = L + (W - L - 10) * (t.time.getEpochSecond() - t0) / (double) (t1 - t0);
                    pts.append(String.format(Locale.ROOT, " %.1f,%.1f", x, py));
                    cum += t.value;
                    py = H - B - (H - B - T) * cum / (double) max;
                    pts.append(String.format(Locale.ROOT, " %.1f,%.1f", x, py));
                    b.append(String.format(Locale.ROOT, "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"3\" fill=\"%s\"><title>%s</title></circle>", x, py, col,
                            h(v + " " + ts(t.time) + ": " + money(t.value) + " to " + t.to + " (total " + money(cum) + ")")));
                }
                pts.append(String.format(Locale.ROOT, " %.1f,%.1f", W - 10, py));
                b.append("<polyline fill=\"none\" stroke=\"").append(col).append("\" stroke-width=\"2\" points=\"").append(pts).append("\"/>");
                legend.append("<span><i class=\"sw\" style=\"background:").append(col).append("\"></i>").append(h(v)).append(" &ndash; ")
                        .append(h(money(cum))).append("</span>");
            }
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\" text-anchor=\"end\">%s</text>", L - 6, T + 10, h(money(max))));
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\" text-anchor=\"end\">0</text>", L - 6, H - B));
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\">%s</text>", L, H - 8, h(ts(Instant.ofEpochSecond(t0)))));
            b.append(String.format(Locale.ROOT, "<text class=\"muted\" x=\"%.0f\" y=\"%.0f\" text-anchor=\"end\">%s</text>", W - 10, H - 8,
                    h(ts(Instant.ofEpochSecond(t1)))));
            return b.append("</svg>").append(legend).append("</div>").toString();
        }
    }

    // =====================================================================
    // Demo data: an investment scam with mule layering, a loop, an account takeover and a dormant mule
    // =====================================================================
    static void writeDemo(Path p) throws IOException {
        Instant base = Instant.parse("2026-03-02T09:00:00Z");
        List<String> r = new ArrayList<>();
        r.add("id,timestamp,from,to,amount,currency,ip,device,memo");

        // The victim is groomed into four "investment" deposits
        add(r, base, 0,    "ACC-VICTIM-01", "ACC-M01", "12000.00", "198.51.100.7", "VICT-LAPTOP", "Investment platform deposit");
        add(r, base, 400,  "ACC-VICTIM-01", "ACC-M01", "7500.00",  "198.51.100.7", "VICT-LAPTOP", "Top-up to unlock withdrawal");
        add(r, base, 900,  "ACC-VICTIM-01", "ACC-M01", "11000.00", "198.51.100.7", "VICT-LAPTOP", "Tax fee");
        add(r, base, 1300, "ACC-VICTIM-01", "ACC-M01", "7500.00",  "198.51.100.7", "VICT-LAPTOP", "Release fee, final");
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

        // Account takeover: ACC-C07's normal habits, then a new device and a large payment to a dormant mule
        add(r, base, -3000, "ACC-C07", "ACC-C02", "45.00",  "192.0.2.107", "C7-DEV", "Lunch");
        add(r, base, -2500, "ACC-C07", "ACC-C11", "120.00", "192.0.2.107", "C7-DEV", "Concert tickets");
        add(r, base, -2000, "ACC-C07", "ACC-C02", "60.00",  "192.0.2.107", "C7-DEV", "");
        add(r, base, -1500, "ACC-C07", "ACC-C15", "85.00",  "192.0.2.107", "C7-DEV", "");
        add(r, base, 1450,  "ACC-C07", "ACC-M10", "4800.00", "203.0.113.50", "DEV-X9", "");
        // ACC-M10 sat unused for five months before it was used to move money
        add(r, base, -216000, "ACC-EMPLOYER", "ACC-M10", "25.00", "192.0.2.90", "EMP-DEV", "Expenses");
        add(r, base, -215000, "ACC-M10", "ACC-SHOP", "20.00", "192.0.2.150", "M10-DEV", "");
        add(r, base, 1500,    "ACC-M10", "EXCHANGE-A", "4750.00", "203.0.113.50", "DEV-77", "");

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
                base.plus(Duration.ofMinutes(minutes)), from, to, amount, ip, dev, csv(memo)));
    }

    // =====================================================================
    // Self-test: known-answer tests built on the demo data
    // =====================================================================
    static final class SelfTest {
        final PrintStream o;
        int pass, fail;

        SelfTest(PrintStream o) { this.o = o; }

        static boolean run(PrintStream o) throws Exception {
            SelfTest t = new SelfTest(o);
            Path dir = Files.createTempDirectory("sherlock-selftest");
            o.println("SHERLOCK " + VERSION + " self-test");
            try { t.all(dir); }
            catch (Exception e) { t.fail++; o.println("  FAIL  unexpected exception: " + e); e.printStackTrace(o); }
            finally {
                try (java.util.stream.Stream<Path> w = Files.walk(dir)) {
                    w.sorted(Comparator.reverseOrder()).forEach(x -> x.toFile().delete());
                }
            }
            o.println("\n" + t.pass + " passed, " + t.fail + " failed");
            return t.fail == 0;
        }

        void check(String name, boolean ok, Object detail) {
            if (ok) { pass++; o.println("  PASS  " + name); }
            else { fail++; o.println("  FAIL  " + name + "   (got: " + detail + ")"); }
        }

        void throwsIAE(String name, Runnable r) {
            try { r.run(); check(name, false, "no error"); }
            catch (IllegalArgumentException e) { check(name, true, null); }
        }

        static Case quiet() { return new Case(new PrintStream(OutputStream.nullOutputStream())); }

        static Case load(Path... files) throws Exception {
            Case c = quiet();
            for (Path f : files) c.loadFile(f, null);
            return c;
        }

        static boolean has(Case c, String acct, String type) {
            return c.findings().stream().anyMatch(f -> f.account.equals(acct) && f.type.equals(type));
        }

        static long held(Trace t, String acct, String label) {
            return t.held().getOrDefault(acct, new TreeMap<>()).getOrDefault(label, 0L);
        }

        static Path write(Path dir, String name, String content) throws IOException {
            Path p = dir.resolve(name);
            Files.write(p, content.getBytes(StandardCharsets.UTF_8));
            return p;
        }

        void all(Path dir) throws Exception {
            o.println("\nAmount parsing");
            check("1,234.56", parseAmount("1,234.56", false).compareTo(new BigDecimal("1234.56")) == 0, parseAmount("1,234.56", false));
            check("pound sign and 'GBP 100.00'", parseAmount("£1,234.56", false).compareTo(new BigDecimal("1234.56")) == 0
                    && parseAmount("GBP 100.00", false).compareTo(new BigDecimal("100")) == 0, "");
            check("minus pound 12.00 is negative", parseAmount("-£12.00", false).compareTo(new BigDecimal("-12")) == 0, "");
            throwsIAE("1.234,56 rejected without --decimal-comma", () -> parseAmount("1.234,56", false));
            check("1.234,56 with --decimal-comma = 1234.56", parseAmount("1.234,56", true).compareTo(new BigDecimal("1234.56")) == 0, "");
            throwsIAE("(500.00) rejected", () -> parseAmount("(500.00)", false));
            throwsIAE("12.50 rejected in decimal-comma mode", () -> parseAmount("12.50", true));
            throwsIAE("1,23 rejected (not a thousands group)", () -> parseAmount("1,23", false));

            o.println("\nTimestamps and CSV");
            Case tz = quiet();
            tz.setParam("tz", "Europe/London", false);
            check("2026-07-01 10:00 in Europe/London = 09:00Z",
                    tz.parseUserTime("2026-07-01 10:00").equals(Instant.parse("2026-07-01T09:00:00Z")), tz.parseUserTime("2026-07-01 10:00"));
            check("explicit Z is not shifted", tz.parseUserTime("2026-07-01T10:00:00Z").equals(Instant.parse("2026-07-01T10:00:00Z")), "");
            check("zone-less time defaults to UTC", quiet().parseUserTime("2026-07-01 10:00").equals(Instant.parse("2026-07-01T10:00:00Z")), "");
            List<Integer> st = new ArrayList<>();
            List<List<String>> rows = parseCsv("id,memo\n1,\"line one\nline two\"\n2,x\n", ',', st, null);
            check("quoted memo with a line break stays one row", rows.size() == 3 && rows.get(1).get(1).equals("line one\nline two")
                    && st.equals(List.of(1, 2, 4)), rows + " " + st);

            o.println("\nDemo case: detectors");
            Path demo = dir.resolve("demo.csv");
            writeDemo(demo);
            Case c = load(demo);
            Map<String, Ranked> rk = c.rankingMap();
            check("ACC-M01 ranks HIGH", rk.containsKey("ACC-M01") && rk.get("ACC-M01").score >= 60, rk.get("ACC-M01") == null ? "absent" : rk.get("ACC-M01").score);
            for (String ty : new String[]{"FAN_IN", "FAN_OUT", "STRUCTURING", "PASS_THROUGH", "SHARED_DEVICE"})
                check("ACC-M01 has " + ty, has(c, "ACC-M01", ty), "missing");
            check("M03 -> M06 -> M07 loop found", has(c, "ACC-M03", "CIRCULAR_FLOW") && has(c, "ACC-M06", "CIRCULAR_FLOW")
                    && has(c, "ACC-M07", "CIRCULAR_FLOW"), "missing");
            check("ACC-VICTIM-01 is LIKELY_VICTIM", has(c, "ACC-VICTIM-01", "LIKELY_VICTIM"), "missing");
            check("ACC-VICTIM-02 is POSSIBLE_VICTIM", has(c, "ACC-VICTIM-02", "POSSIBLE_VICTIM"), "missing");
            check("victims are not in the suspicion ranking", !rk.containsKey("ACC-VICTIM-01"), "present");
            check("ACC-C07 account takeover found", has(c, "ACC-C07", "ACCOUNT_TAKEOVER"), "missing");
            check("ACC-M10 flagged as takeover payee and dormant", has(c, "ACC-M10", "ATO_PAYEE") && has(c, "ACC-M10", "DORMANT_REACTIVATED"), "missing");
            Finding sf = c.findings().stream().filter(f -> f.type.equals("STRUCTURING") && f.account.equals("ACC-M01")).findFirst().orElse(null);
            check("findings cite transaction ids", sf != null && sf.txIds.size() >= 3, sf == null ? "none" : sf.txIds);
            c.setParam("threshold", "10000,5000", false);
            check("several structuring thresholds accepted", c.s.thresholds.equals(List.of(1_000_000L, 500_000L)), c.s.thresholds);
            c.setParam("threshold", "10000", false);
            c.exec(List.of("disable", "fan-in"));
            check("disabled detector produces nothing", c.findings().stream().noneMatch(f -> f.type.equals("FAN_IN")), "FAN_IN present");
            c.exec(List.of("enable", "fan-in"));

            o.println("\nDemo case: tracing");
            Map<Tx, String> seeds = c.seedsFor(List.of("ACC-VICTIM-01"), null);
            Trace tf = c.runTrace(seeds, "tainted-first", null);
            check("tainted-first: EXCHANGE-A 19,000.00 (same as v1)", held(tf, "EXCHANGE-A", "ACC-VICTIM-01") == 1_900_000, money(held(tf, "EXCHANGE-A", "ACC-VICTIM-01")));
            check("tainted-first: EXCHANGE-B 9,200.00 (same as v1)", held(tf, "EXCHANGE-B", "ACC-VICTIM-01") == 920_000, money(held(tf, "EXCHANGE-B", "ACC-VICTIM-01")));
            check("tainted-first: EXCHANGE-C 9,200.00 (same as v1)", held(tf, "EXCHANGE-C", "ACC-VICTIM-01") == 920_000, money(held(tf, "EXCHANGE-C", "ACC-VICTIM-01")));
            for (String m : MODES) {
                Trace t = c.runTrace(seeds, m, null);
                long located = 0;
                for (TreeMap<String, Long> v : t.held().values()) located += total(v);
                check(m + ": every penny accounted for (38,000.00)", t.seededTotal() == 3_800_000 && located == 3_800_000, money(located));
            }
            Trace pr = c.runTrace(seeds, "prorata", null);
            check("prorata: 38/48 share leaves ACC-M01, 237.50 stays", Math.abs(held(pr, "ACC-M01", "ACC-VICTIM-01") - 23_750) <= 5,
                    money(held(pr, "ACC-M01", "ACC-VICTIM-01")));
            check("fifo: nothing of VICTIM-01's money stays in ACC-M01", held(c.runTrace(seeds, "fifo", null), "ACC-M01", "ACC-VICTIM-01") == 0, "");
            check("clean-first: 300.00 stays in ACC-M01",
                    held(c.runTrace(seeds, "clean-first", null), "ACC-M01", "ACC-VICTIM-01") == 30_000, "");
            Map<Tx, String> multi = c.seedsFor(List.of("ACC-VICTIM-01", "ACC-VICTIM-02"), null);
            Trace mt = c.runTrace(multi, "prorata", null);
            check("multi-victim trace keeps victims separate", mt.seeded.get("ACC-VICTIM-01") == 3_800_000 && mt.seeded.get("ACC-VICTIM-02") == 200_000
                    && held(mt, "EXCHANGE-A", "ACC-VICTIM-02") > 0, mt.seeded);
            Trace rv = c.runTrace(Map.of(), "prorata", "EXCHANGE-A");
            check("reverse trace accounts for everything EXCHANGE-A received", total(rv.intoTarget) == rv.targetReceived && rv.targetReceived == 2_375_000,
                    money(total(rv.intoTarget)) + " of " + money(rv.targetReceived));
            check("reverse trace finds ACC-VICTIM-01 as an origin", rv.intoTarget.getOrDefault("ACC-VICTIM-01", 0L) > 0, rv.intoTarget.keySet());

            o.println("\nLoops, scores, look-ups");
            Path loop = write(dir, "loop.csv", "id,timestamp,from,to,amount\n"
                    + "L1,2026-01-01T10:00:00Z,A,B,5000\nL2,2026-01-05T10:00:00Z,B,C,5000\nL3,2026-01-03T10:00:00Z,C,A,5000\n"
                    + "L4,2026-02-01T10:00:00Z,X,Y,5000\nL5,2026-02-01T12:00:00Z,Y,Z,5000\nL6,2026-02-01T14:00:00Z,Z,X,5000\n");
            Case lc = load(loop);
            check("loop out of time order is NOT flagged", !has(lc, "A", "CIRCULAR_FLOW"), "flagged");
            check("loop in time order IS flagged", has(lc, "X", "CIRCULAR_FLOW") && has(lc, "Z", "CIRCULAR_FLOW"), "missing");
            Path shared = write(dir, "shared.csv", "id,timestamp,from,to,amount,device\n"
                    + "S1,2026-01-01T10:00:00Z,P,Q,10,D1\nS2,2026-01-01T11:00:00Z,R,Q,10,D1\nS3,2026-01-01T12:00:00Z,P,Q,10,D2\n"
                    + "S4,2026-01-01T13:00:00Z,R,Q,10,D2\n");
            Case sc = load(shared);
            check("two shared devices still score 25, not 50", sc.rankingMap().get("P").score == 25, sc.rankingMap().get("P").score);
            check("account names are case-insensitive", c.resolve("acc-m01").equals("ACC-M01"), "");
            throwsIAE("ambiguous partial name is refused", () -> c.resolve("M0"));

            o.println("\nSeveral files, mappings, currencies");
            Path bankB = write(dir, "bank-b.csv", "id,timestamp,from,to,amount,currency,memo\n"
                    + "B-1,2026-03-02T11:00:00Z,ACC-VICTIM-01,ACC-M01,12000.00,GBP,Seen by the receiving bank\n"
                    + "B-2,2026-03-03T11:00:00Z,ACC-M01,ACC-NEW,50.00,GBP,\n");
            Case dc = load(demo, bankB);
            check("the same payment in two files is merged once", dc.merges.size() == 1 && dc.txs.size() == c.txs.size() + 1,
                    dc.merges.size() + " merges, " + dc.txs.size() + " txs");
            try { dc.loadFile(demo, null); check("identical file refused", false, "loaded"); }
            catch (IllegalArgumentException e) { check("identical file refused", true, null); }

            String stmt = "Barclays export\nDate,Time,Description,Counterparty,Paid out,Paid in\n"
                    + "01/07/2026,10:00,£ transfer to X,ACC-X,\"1,234.56\",\n"
                    + "02/07/2026,09:30,Refund,ACC-Y,,25.00\n"
                    + "03/07/2026,09:30,Odd row,ACC-Z,(50.00),\n";
            Path stmtFile = dir.resolve("stmt.csv");
            Files.write(stmtFile, stmt.getBytes(Charset.forName("windows-1252")));
            Path map = write(dir, "bank.properties", "name=Test bank\nowner=ACC-S1\ncounterparty=Counterparty\ndebit=Paid out\ncredit=Paid in\n"
                    + "date=Date\ntime=Time\ndate.format=dd/MM/yyyy\ntime.format=HH:mm\ntz=Europe/London\nmemo=Description\nskiplines=1\n");
            Case mc = quiet();
            mc.loadFile(stmtFile, map);
            Tx m1 = mc.txs.isEmpty() ? null : mc.txs.get(0);
            check("statement row becomes ACC-S1 -> ACC-X 1,234.56 at 09:00Z", m1 != null && m1.from.equals("ACC-S1") && m1.to.equals("ACC-X")
                    && m1.value == 123_456 && m1.time.equals(Instant.parse("2026-07-01T09:00:00Z")), m1 == null ? "none" : m1.from + "->" + m1.to + " " + m1.value + " " + m1.time);
            check("paid-in row is money IN to the owner", mc.txs.size() > 1 && mc.txs.get(1).from.equals("ACC-Y") && mc.txs.get(1).to.equals("ACC-S1"), "");
            check("windows-1252 pound sign decoded", m1 != null && m1.memo.contains("£") && mc.sources.get(0).encoding.equals("windows-1252"), m1 == null ? "" : m1.memo);
            check("bracketed amount skipped with a reason", mc.skipped.size() == 1 && mc.skipped.get(0).contains("bracketed"), mc.skipped);

            Path fx = write(dir, "fx.csv", "id,timestamp,from,to,amount,currency\nF1,2026-03-02T10:00:00Z,E1,E2,1000.00,EUR\nF2,2026-03-02T10:00:00Z,U1,U2,10.00,USD\n");
            Path rates = write(dir, "rates.csv", "date,currency,rate\n2026-03-01,EUR,0.85\n");
            Case fc = load(fx);
            fc.loadRates(rates);
            check("EUR 1000.00 converted at 0.85 = 850.00 GBP", fc.byId.get("F1").value == 85_000, fc.byId.get("F1").value);
            check("unconverted USD is warned about", !fc.byId.get("F2").converted && fc.dataWarnings().stream().anyMatch(x -> x.contains("USD")), "");

            Path wl = write(dir, "watch.csv", "type,value,note\ndevice,DEV-77,seen in another case\n");
            Case wc = load(demo);
            wc.loadWatchlist(wl);
            check("watchlisted device flags ACC-M01", has(wc, "ACC-M01", "WATCHLIST"), "missing");

            o.println("\nOutputs");
            Path html = dir.resolve("case.html"), txt = dir.resolve("case.txt"), dot = dir.resolve("g.dot");
            c.report(html, List.of("ACC-VICTIM-01"));
            c.report(txt, List.of("ACC-VICTIM-01"));
            c.exec(List.of("export", "dot", dot.toString(), "ACC-VICTIM-01"));
            c.exec(List.of("export", "csv", dir.resolve("graph").toString()));
            String hs = Files.readString(html), ts = Files.readString(txt);
            check("HTML report has a Sankey diagram and the ranking", hs.contains("<svg") && hs.contains("Sankey") && hs.contains("ACC-M01"), "");
            check("text report lists every skipped row, settings and the audit log", ts.contains("== SETTINGS ==") && ts.contains("== AUDIT LOG =="), "");
            check("DOT and CSV exports written", Files.readString(dot).contains("digraph") && Files.exists(dir.resolve("graph-entities.csv"))
                    && Files.readString(dir.resolve("graph-links.csv")).startsWith("Source,Target,Weight"), "");
            check("audit log records commands", c.audit.stream().anyMatch(x -> x.contains("export dot")), c.audit);

            Path cfg = dir.resolve("s.properties");
            c.setParam("structmin", "4", false);
            c.setParam("tracemode", "prorata", false);
            c.saveConfig(cfg);
            Case cc = quiet();
            cc.loadConfig(cfg);
            check("settings survive saveconfig / config", cc.s.structMin == 4 && cc.s.traceMode.equals("prorata"), cc.s.structMin + " " + cc.s.traceMode);
        }
    }
}
