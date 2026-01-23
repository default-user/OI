/*
 * flourish.java — “God code” level (single-file Java)
 *
 * WHAT THIS IS:
 * A hardened, fail-closed OI action gateway with:
 *   - CIF: strict input gating (content-type allowlist, size limits, conservative block heuristics)
 *   - CDI: policy gate (tool allowlist, network disable by default)
 *   - CCC (Covenanted Capability Control): action requires:
 *       (1) Non-replayable, action-bound CONSENT token (Ed25519, exp+nonce+act_hash+aud)
 *       (2) Scoped CAPABILITY token (Ed25519, exp+scopes+aud)
 *       (3) Tamper-evident AUDIT chain (hash-chained, persisted)
 *   - Replay prevention (nonce cache)
 *   - Per-IP rate limiting (token bucket)
 *   - Fail-closed by default
 *
 * BUILD / RUN (Java 17+; Java 21 recommended):
 *   javac flourish.java
 *   java --add-modules jdk.httpserver Flourish
 *
 * SERVER:
 *   http://127.0.0.1:8088
 *
 * ENDPOINTS:
 *   GET  /healthz
 *   POST /v1/ask
 *   POST /v1/tool/run
 *   GET  /v1/audit/tail?n=25
 *
 * DEV ONLY (disabled by default):
 *   POST /v1/dev/consent/mint   (mint consent tokens)
 *   POST /v1/dev/cap/mint       (mint capability tokens)
 *
 * IMPORTANT:
 * - In production, DO NOT expose dev mint endpoints.
 * - Persist keys securely (this monolith generates keys on startup for demo portability).
 * - Keep network tools disabled unless you have a controlled allowlist + extra gates.
 */

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public class Flourish {

  // ------------------------- Config -------------------------
  static final class Config {
    final String host = "127.0.0.1";
    final int port = 8088;

    final boolean failClosed = true;
    final int maxBodyBytes = 16_384;

    final Set<String> allowedContentTypes = Set.of("application/json");
    final List<String> blockPatterns = List.of("ignore previous","system prompt","exfiltrate","bypass","jailbreak");

    // CDI policy
    final Set<String> allowTools = Set.of("echo","time"); // net/http_get exists but is not allowed
    final boolean allowNetworkTools = false;

    // CCC requirements
    final boolean requireConsent = true;
    final boolean requireCapabilityForTools = true;

    // Token audiences (bind tokens to this service)
    final String consentAudience = "oi-runtime";
    final String capAudience = "oi-runtime";

    // TTLs (short consent TTL; longer cap TTL)
    final int consentTtlSeconds = 120;
    final int capTtlSeconds = 3600;

    // Replay cache TTL (>= consent TTL)
    final int nonceTtlSeconds = 300;

    // Rate limiting
    final int rpmPerIp = 30;

    // Audit persistence
    final String auditFilePath = "audit.log";

    // Dev endpoints (default off)
    final boolean enableDevMint = false;
  }

  // ------------------------- Security headers -------------------------
  static void setSecurityHeaders(HttpExchange ex) {
    Headers h = ex.getResponseHeaders();
    h.set("X-Content-Type-Options", "nosniff");
    h.set("X-Frame-Options", "DENY");
    h.set("Referrer-Policy", "no-referrer");
    h.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  }

  // ------------------------- Minimal JSON (no deps) -------------------------
  static final class MiniJson {
    private final String s; private int i;
    private MiniJson(String s){this.s=s;this.i=0;}
    static Object parse(String s){MiniJson p=new MiniJson(s);p.ws();Object v=p.val();p.ws();if(p.i!=p.s.length())throw new RuntimeException("json trailing");return v;}
    static String q(String s){StringBuilder b=new StringBuilder("\"");for(char c: s.toCharArray()){switch(c){
      case '"':b.append("\\\"");break; case '\\':b.append("\\\\");break; case '\n':b.append("\\n");break;
      case '\r':b.append("\\r");break; case '\t':b.append("\\t");break; default: if(c<0x20)b.append(String.format("\\u%04x",(int)c)); else b.append(c);} } return b.append("\"").toString();}
    static String str(Object o){
      if(o==null)return "null";
      if(o instanceof String)return q((String)o);
      if(o instanceof Number || o instanceof Boolean)return o.toString();
      if(o instanceof Map){
        @SuppressWarnings("unchecked") Map<String,Object> m=(Map<String,Object>)o;
        StringBuilder b=new StringBuilder("{"); boolean first=true;
        for(var e: m.entrySet()){ if(!first)b.append(","); first=false; b.append(q(e.getKey())).append(":").append(str(e.getValue()));}
        return b.append("}").toString();
      }
      if(o instanceof List){
        @SuppressWarnings("unchecked") List<Object> a=(List<Object>)o;
        StringBuilder b=new StringBuilder("[");
        for(int k=0;k<a.size();k++){ if(k>0)b.append(","); b.append(str(a.get(k))); }
        return b.append("]").toString();
      }
      return q(o.toString());
    }
    private Object val(){ws(); if(i>=s.length())throw new RuntimeException("json eof"); char c=s.charAt(i);
      if(c=='{')return obj(); if(c=='[')return arr(); if(c=='"')return strv(); if(c=='t'||c=='f')return bool();
      if(c=='n')return nul(); if(c=='-'||Character.isDigit(c))return num(); throw new RuntimeException("json bad");}
    private Map<String,Object> obj(){eat('{'); Map<String,Object> m=new LinkedHashMap<>(); ws(); if(peek('}')){i++;return m;}
      while(true){ws(); String k=strv(); ws(); eat(':'); Object v=val(); m.put(k,v); ws(); if(peek('}')){i++;break;} eat(',');} return m;}
    private List<Object> arr(){eat('['); List<Object> a=new ArrayList<>(); ws(); if(peek(']')){i++;return a;}
      while(true){a.add(val()); ws(); if(peek(']')){i++;break;} eat(',');} return a;}
    private String strv(){eat('"'); StringBuilder b=new StringBuilder(); while(i<s.length()){char c=s.charAt(i++);
      if(c=='"')break; if(c=='\\'){char e=s.charAt(i++); switch(e){case '"':b.append('"');break;case '\\':b.append('\\');break;
        case 'n':b.append('\n');break;case 'r':b.append('\r');break;case 't':b.append('\t');break;
        case 'u': String hex=s.substring(i,i+4); i+=4; b.append((char)Integer.parseInt(hex,16)); break;
        default: throw new RuntimeException("json escape");}} else b.append(c);} return b.toString();}
    private Boolean bool(){ if(s.startsWith("true",i)){i+=4;return true;} if(s.startsWith("false",i)){i+=5;return false;} throw new RuntimeException("json bool");}
    private Object nul(){ if(s.startsWith("null",i)){i+=4;return null;} throw new RuntimeException("json null");}
    private Number num(){ int st=i; if(s.charAt(i)=='-')i++; while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;
      boolean fl=false; if(i<s.length()&&s.charAt(i)=='.'){fl=true;i++; while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;}
      if(i<s.length()&&(s.charAt(i)=='e'||s.charAt(i)=='E')){fl=true;i++; if(i<s.length()&&(s.charAt(i)=='+'||s.charAt(i)=='-'))i++;
        while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;}
      String n=s.substring(st,i);
      if(!fl){ long v=Long.parseLong(n); if(v>=Integer.MIN_VALUE&&v<=Integer.MAX_VALUE)return (int)v; return v;}
      return Double.parseDouble(n);}
    private void ws(){ while(i<s.length()){char c=s.charAt(i); if(c==' '||c=='\n'||c=='\r'||c=='\t')i++; else break;}}
    private boolean peek(char c){ return i<s.length()&&s.charAt(i)==c;}
    private void eat(char c){ if(i>=s.length()||s.charAt(i)!=c)throw new RuntimeException("json exp "+c); i++; }
  }

  // ------------------------- Hash utils -------------------------
  static String sha256Hex(byte[] b) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] out = md.digest(b);
      StringBuilder sb = new StringBuilder(out.length*2);
      for (byte x : out) sb.append(String.format("%02x", x));
      return sb.toString();
    } catch (Exception e) { throw new RuntimeException(e); }
  }

  static String sha256Hex(String s) { return sha256Hex(s.getBytes(StandardCharsets.UTF_8)); }

  // ------------------------- Audit (hash-chain + persisted) -------------------------
  static final class Audit {
    private final File file;
    private final Object lock = new Object();
    private String head;

    Audit(String path) {
      this.file = new File(path);
      // initialize head by reading last hash if file exists
      this.head = "GENESIS";
      if (file.exists()) {
        String last = readLastHash(file);
        if (last != null) head = last;
      } else {
        append("GENESIS", "start");
      }
    }

    String append(String kind, String msg) {
      long ts = Instant.now().getEpochSecond();
      synchronized (lock) {
        String prev = head;
        String h = sha256Hex(prev + "|" + kind + "|" + msg + "|" + ts);
        head = h;
        String line = ts + "\t" + kind + "\t" + prev + "\t" + h + "\t" + sanitize(msg) + "\n";
        try (FileOutputStream fos = new FileOutputStream(file, true)) {
          fos.write(line.getBytes(StandardCharsets.UTF_8));
          fos.getFD().sync();
        } catch (IOException e) {
          // If audit can't persist and we're fail-closed, the caller should deny.
        }
        return h;
      }
    }

    boolean canPersist() {
      try (FileOutputStream fos = new FileOutputStream(file, true)) {
        fos.write(new byte[0]);
        fos.getFD().sync();
        return true;
      } catch (IOException e) {
        return false;
      }
    }

    List<Map<String,Object>> tail(int n) {
      if (n <= 0) n = 25;
      List<String> lines = new ArrayList<>();
      try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
        long len = raf.length();
        long pos = Math.max(0, len - 128_000);
        raf.seek(pos);
        if (pos > 0) raf.readLine();
        String line;
        while ((line = raf.readLine()) != null) lines.add(new String(line.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8));
      } catch (IOException ignored) {}
      int start = Math.max(0, lines.size() - n);
      List<Map<String,Object>> out = new ArrayList<>();
      for (int i=start; i<lines.size(); i++) {
        String[] p = lines.get(i).split("\t", 5);
        if (p.length < 4) continue;
        Map<String,Object> m = new LinkedHashMap<>();
        m.put("ts", Long.parseLong(p[0]));
        m.put("kind", p[1]);
        m.put("prev", p[2]);
        m.put("hash", p[3]);
        m.put("msg", (p.length==5)?p[4]:"");
        out.add(m);
      }
      return out;
    }

    static String sanitize(String s){ return s==null? "": s.replace("\n"," ").replace("\r"," "); }

    static String readLastHash(File f) {
      try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
        long len = raf.length();
        if (len == 0) return null;
        long pos = Math.max(0, len - 256_000);
        raf.seek(pos);
        if (pos > 0) raf.readLine();
        String line, last=null;
        while ((line = raf.readLine()) != null) last=line;
        if (last==null) return null;
        String[] p = new String(last.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8).split("\t", 5);
        return (p.length>=4)? p[3] : null;
      } catch (IOException e) { return null; }
    }
  }

  // ------------------------- Rate limiter (token bucket per route+ip) -------------------------
  static final class RateLimiter {
    static final class Bucket { double tokens; long lastMs; Bucket(double t,long ms){tokens=t;lastMs=ms;} }
    private final int cap;
    private final double refillPerMs;
    private final ConcurrentHashMap<String, Bucket> map = new ConcurrentHashMap<>();

    RateLimiter(int rpm) {
      this.cap = Math.max(5, rpm);
      this.refillPerMs = (double) cap / 60_000.0;
    }

    boolean allow(String key) {
      long now = System.currentTimeMillis();
      Bucket b = map.computeIfAbsent(key, k -> new Bucket(cap, now));
      synchronized (b) {
        long dt = now - b.lastMs;
        if (dt > 0) {
          b.tokens = Math.min(cap, b.tokens + dt * refillPerMs);
          b.lastMs = now;
        }
        if (b.tokens >= 1.0) { b.tokens -= 1.0; return true; }
        return false;
      }
    }
  }

  // ------------------------- Nonce cache (replay prevention) -------------------------
  static final class NonceCache {
    private final ConcurrentHashMap<String, Long> seen = new ConcurrentHashMap<>();
    private final long ttlSec;
    NonceCache(long ttlSec){ this.ttlSec=ttlSec; }

    boolean checkAndStore(String nonce) {
      if (nonce == null || nonce.isBlank()) return false;
      long now = Instant.now().getEpochSecond();
      cleanup(now);
      return seen.putIfAbsent(nonce, now) == null;
    }

    void cleanup(long now) {
      for (var e : seen.entrySet()) {
        if (now - e.getValue() > ttlSec) seen.remove(e.getKey(), e.getValue());
      }
    }
  }

  // ------------------------- Tokens (Ed25519) -------------------------
  static final class SigBox {
    final String kid;
    final KeyPair kp;

    SigBox(String kid) {
      this.kid = kid;
      try {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        this.kp = kpg.generateKeyPair();
      } catch (Exception e) { throw new RuntimeException("Ed25519 unavailable", e); }
    }

    byte[] sign(byte[] msg) throws Exception {
      Signature s = Signature.getInstance("Ed25519");
      s.initSign(kp.getPrivate());
      s.update(msg);
      return s.sign();
    }

    boolean verify(byte[] msg, byte[] sig) throws Exception {
      Signature s = Signature.getInstance("Ed25519");
      s.initVerify(kp.getPublic());
      s.update(msg);
      return s.verify(sig);
    }

    static String b64url(byte[] b){ return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    static byte[] b64urlDec(String s){ return Base64.getUrlDecoder().decode(s); }
  }

  // Consent token payload: {v,kid,aud,exp,nonce,act_hash}
  // Cap token payload: {v,kid,aud,exp,scopes[]}
  static String canonicalJsonSorted(Map<String,Object> payload) {
    List<String> keys = new ArrayList<>(payload.keySet());
    Collections.sort(keys);
    Map<String,Object> out = new LinkedHashMap<>();
    for (String k : keys) out.put(k, payload.get(k));
    return MiniJson.str(out);
  }

  static String mintConsent(SigBox box, String aud, int ttlSec, String nonce, String actHash) throws Exception {
    long exp = Instant.now().getEpochSecond() + ttlSec;
    Map<String,Object> p = new LinkedHashMap<>();
    p.put("v", 1);
    p.put("kid", box.kid);
    p.put("aud", aud);
    p.put("exp", exp);
    p.put("nonce", nonce);
    p.put("act_hash", actHash);
    String json = canonicalJsonSorted(p);
    byte[] sig = box.sign(json.getBytes(StandardCharsets.UTF_8));
    return SigBox.b64url(json.getBytes(StandardCharsets.UTF_8)) + "." + SigBox.b64url(sig);
  }

  static Map<String,Object> verifySignedToken(SigBox box, String token) throws Exception {
    String[] parts = token.split("\\.");
    if (parts.length != 2) throw new Exception("bad token");
    byte[] payload = SigBox.b64urlDec(parts[0]);
    byte[] sig = SigBox.b64urlDec(parts[1]);
    if (!box.verify(payload, sig)) throw new Exception("sig invalid");
    Object parsed = MiniJson.parse(new String(payload, StandardCharsets.UTF_8));
    if (!(parsed instanceof Map)) throw new Exception("payload not object");
    @SuppressWarnings("unchecked") Map<String,Object> m = (Map<String,Object>) parsed;
    // exp check
    Object expO = m.get("exp");
    if (!(expO instanceof Number)) throw new Exception("missing exp");
    long exp = ((Number)expO).longValue();
    if (Instant.now().getEpochSecond() > exp) throw new Exception("token expired");
    return m;
  }

  static String asString(Object o){ return (o instanceof String) ? (String)o : null; }
  static int asInt(Object o, int d){ return (o instanceof Number) ? ((Number)o).intValue() : d; }

  // ------------------------- CIF -------------------------
  static final class CIF {
    final Config cfg;
    final List<String> blockedLower;
    CIF(Config cfg){
      this.cfg=cfg;
      blockedLower=new ArrayList<>();
      for(String p: cfg.blockPatterns) blockedLower.add(p.toLowerCase(Locale.ROOT));
    }

    byte[] readChecked(HttpExchange ex) throws Exception {
      String method = ex.getRequestMethod().toUpperCase(Locale.ROOT);
      if (method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) {
        String ct = ex.getRequestHeaders().getFirst("Content-Type");
        ct = (ct==null) ? "" : ct.toLowerCase(Locale.ROOT);
        boolean ok=false;
        for (String a : cfg.allowedContentTypes) {
          if (ct.startsWith(a.toLowerCase(Locale.ROOT))) { ok=true; break; }
        }
        if (!ok && cfg.failClosed) throw new Exception("CIF: disallowed Content-Type");
      }

      InputStream in = ex.getRequestBody();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      byte[] buf = new byte[4096];
      int total=0, r;
      while ((r=in.read(buf))!=-1) {
        total += r;
        if (total > cfg.maxBodyBytes) {
          if (cfg.failClosed) throw new Exception("CIF: body too large");
          break;
        }
        baos.write(buf,0,r);
      }
      byte[] body = baos.toByteArray();

      String low = new String(body, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
      for (String p : blockedLower) {
        if (!p.isBlank() && low.contains(p) && cfg.failClosed) throw new Exception("CIF: blocked pattern detected");
      }
      return body;
    }
  }

  // ------------------------- CDI -------------------------
  static final class CDI {
    final Config cfg;
    final Set<String> toolsLower;
    CDI(Config cfg){
      this.cfg=cfg;
      toolsLower=new HashSet<>();
      for(String t: cfg.allowTools) toolsLower.add(t.toLowerCase(Locale.ROOT));
    }

    String checkToolAllowed(String tool) {
      if (tool==null || tool.isBlank()) return "CDI: missing tool";
      String t = tool.toLowerCase(Locale.ROOT);
      if (!toolsLower.contains(t)) return "CDI: tool not allowed by policy";
      if (t.startsWith("net/") && !cfg.allowNetworkTools) return "CDI: network tools disabled";
      return null;
    }
  }

  // ------------------------- Tools -------------------------
  static final class Tools {
    Map<String,Object> run(String tool, Map<String,String> args) throws Exception {
      if ("echo".equals(tool)) return Map.of("echo", args==null?Map.of():args);
      if ("time".equals(tool)) return Map.of("utc", Instant.now().toString());
      if ("net/http_get".equals(tool)) throw new UnsupportedOperationException("net/http_get disabled");
      throw new IllegalArgumentException("unknown tool");
    }
  }

  // ------------------------- App -------------------------
  static final class App {
    final Config cfg = new Config();

    final Audit audit = new Audit(cfg.auditFilePath);
    final RateLimiter rl = new RateLimiter(cfg.rpmPerIp);
    final NonceCache nonces = new NonceCache(cfg.nonceTtlSeconds);

    final CIF cif = new CIF(cfg);
    final CDI cdi = new CDI(cfg);
    final Tools tools = new Tools();

    // NOTE: keys are generated at startup for portability.
    // Production: load keys from disk/keystore and rotate via kid.
    final SigBox consentKeys = new SigBox("consent-root");
    final SigBox capKeys = new SigBox("cap-root");

    String clientIp(HttpExchange ex) {
      InetSocketAddress ra = ex.getRemoteAddress();
      return (ra==null) ? "unknown" : ra.getAddress().getHostAddress();
    }

    boolean rateOk(HttpExchange ex, String route) {
      return rl.allow(route + "|" + clientIp(ex));
    }

    void json(HttpExchange ex, int status, Object body) throws IOException {
      setSecurityHeaders(ex);
      byte[] b = MiniJson.str(body).getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type","application/json");
      ex.sendResponseHeaders(status, b.length);
      try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    // Compute action hash from canonical JSON of the action object
    String computeActHash(String canonicalActionJson) {
      return sha256Hex(canonicalActionJson.getBytes(StandardCharsets.UTF_8));
    }

    // Verify consent token (nonce+act_hash+aud)
    void verifyConsent(String consentToken, String expectedActHash) throws Exception {
      if (!cfg.requireConsent) return;
      if (consentToken==null || consentToken.isBlank()) throw new Exception("CDI: missing consent token");

      Map<String,Object> p = verifySignedToken(consentKeys, consentToken);
      if (asInt(p.get("v"), -1) != 1) throw new Exception("consent bad version");

      String aud = asString(p.get("aud"));
      if (!cfg.consentAudience.equals(aud)) throw new Exception("consent bad aud");

      String nonce = asString(p.get("nonce"));
      if (!nonces.checkAndStore(nonce)) throw new Exception("consent replay or missing nonce");

      String actHash = asString(p.get("act_hash"));
      if (actHash==null || !actHash.equals(expectedActHash)) throw new Exception("consent act_hash mismatch");
    }

    // Verify capability token for tool scope, audience
    void verifyCap(String capToken, String tool) throws Exception {
      if (!cfg.requireCapabilityForTools) return;
      if (!cfg.failClosed) return;
      if (capToken==null || capToken.isBlank()) throw new Exception("missing cap token");

      Map<String,Object> p = verifySignedToken(capKeys, capToken);
      if (asInt(p.get("v"), -1) != 1) throw new Exception("cap bad version");

      String aud = asString(p.get("aud"));
      if (!cfg.capAudience.equals(aud)) throw new Exception("cap bad aud");

      Object scopesO = p.get("scopes");
      if (!(scopesO instanceof List)) throw new Exception("cap scopes missing");
      @SuppressWarnings("unchecked") List<Object> scopes = (List<Object>) scopesO;

      String want = "tool:" + tool;
      boolean ok=false;
      for (Object s : scopes) if (want.equals(s)) { ok=true; break; }
      if (!ok) throw new Exception("missing scope " + want);
    }

    HttpHandler healthz() {
      return ex -> {
        if (!rateOk(ex,"healthz")) { json(ex,429,Map.of("error","rate limited")); return; }
        json(ex,200,Map.of("ok",true));
      };
    }

    HttpHandler auditTail() {
      return ex -> {
        if (!rateOk(ex,"audit")) { json(ex,429,Map.of("error","rate limited")); return; }
        String nStr = Optional.ofNullable(ex.getRequestURI().getRawQuery()).orElse("");
        int n=25;
        for (String p : nStr.split("&")) if (p.startsWith("n=")) { try { n=Integer.parseInt(p.substring(2)); } catch(Exception ignored){} }
        json(ex,200,audit.tail(n));
      };
    }

    // /v1/ask
    HttpHandler ask() {
      return ex -> {
        if (!rateOk(ex,"ask")) { json(ex,429,Map.of("error","rate limited")); return; }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { json(ex,405,Map.of("error","method not allowed")); return; }
        try {
          if (cfg.failClosed && !audit.canPersist()) throw new Exception("audit unavailable");

          byte[] body = cif.readChecked(ex);
          Object parsed = MiniJson.parse(new String(body, StandardCharsets.UTF_8));
          if (!(parsed instanceof Map)) throw new Exception("bad json");
          @SuppressWarnings("unchecked") Map<String,Object> m=(Map<String,Object>) parsed;

          String consentToken = (m.get("consent_token") instanceof String) ? (String)m.get("consent_token") : null;
          String prompt = (m.get("prompt") instanceof String) ? (String)m.get("prompt") : "";

          // Action object for hashing (bind consent to exact action)
          Map<String,Object> action = new LinkedHashMap<>();
          action.put("op","ask");
          action.put("prompt", prompt);
          String canonical = canonicalJsonSorted(action);
          String actHash = computeActHash(canonical);

          verifyConsent(consentToken, actHash);

          // Model stub: replace with real adapter behind CDI
          String out = "MODEL_STUB: " + prompt;

          String ref = audit.append("ASK_ALLOW", "ok");
          json(ex,200,Map.of("output",out,"receipt",Map.of("decision","ALLOW","reason","ok","audit_ref",ref)));
        } catch (Exception e) {
          String ref = audit.append("ASK_DENY", e.getMessage());
          int code = (e.getMessage()!=null && e.getMessage().startsWith("CIF:")) ? 400 : 403;
          json(ex,code,Map.of("output","", "receipt",Map.of("decision","DENY","reason",e.getMessage(),"audit_ref",ref)));
        }
      };
    }

    // /v1/tool/run
    HttpHandler toolRun() {
      return ex -> {
        if (!rateOk(ex,"tool")) { json(ex,429,Map.of("error","rate limited")); return; }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { json(ex,405,Map.of("error","method not allowed")); return; }
        try {
          if (cfg.failClosed && !audit.canPersist()) throw new Exception("audit unavailable");

          byte[] body = cif.readChecked(ex);
          Object parsed = MiniJson.parse(new String(body, StandardCharsets.UTF_8));
          if (!(parsed instanceof Map)) throw new Exception("bad json");
          @SuppressWarnings("unchecked") Map<String,Object> m=(Map<String,Object>) parsed;

          String consentToken = (m.get("consent_token") instanceof String) ? (String)m.get("consent_token") : null;
          String capToken = (m.get("cap_token") instanceof String) ? (String)m.get("cap_token") : null;
          String tool = (m.get("tool") instanceof String) ? (String)m.get("tool") : null;

          String deny = cdi.checkToolAllowed(tool);
          if (deny != null) throw new Exception(deny);

          Map<String,String> args = new LinkedHashMap<>();
          Object a = m.get("args");
          if (a instanceof Map) {
            @SuppressWarnings("unchecked") Map<String,Object> raw=(Map<String,Object>)a;
            for (var e : raw.entrySet()) args.put(e.getKey(), String.valueOf(e.getValue()));
          }

          // Bind consent to exact action payload
          Map<String,Object> action = new LinkedHashMap<>();
          action.put("op","tool/run");
          action.put("tool", tool);
          action.put("args", args);
          String canonical = canonicalJsonSorted(action);
          String actHash = computeActHash(canonical);

          verifyConsent(consentToken, actHash);
          verifyCap(capToken, tool);

          Map<String,Object> result = tools.run(tool, args);
          String ref = audit.append("TOOL_OK", tool);
          json(ex,200,Map.of("result",result,"receipt",Map.of("decision","ALLOW","reason","ok","audit_ref",ref)));
        } catch (Exception e) {
          String ref = audit.append("TOOL_DENY", e.getMessage());
          json(ex,403,Map.of("error",e.getMessage(),"receipt",Map.of("decision","DENY","reason",e.getMessage(),"audit_ref",ref)));
        }
      };
    }

    // DEV endpoints (mint tokens). Disabled by default.
    HttpHandler devConsentMint() {
      return ex -> {
        if (!cfg.enableDevMint) { json(ex,404,Map.of("error","not found")); return; }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { json(ex,405,Map.of("error","method not allowed")); return; }
        try {
          byte[] body = cif.readChecked(ex);
          Object parsed = MiniJson.parse(new String(body, StandardCharsets.UTF_8));
          if (!(parsed instanceof Map)) throw new Exception("bad json");
          @SuppressWarnings("unchecked") Map<String,Object> m=(Map<String,Object>)parsed;

          // caller supplies act_json (canonical or not; we canonicalize via parse->stringify sorted)
          String actJson = (m.get("act_json") instanceof String) ? (String)m.get("act_json") : null;
          if (actJson==null || actJson.isBlank()) throw new Exception("missing act_json");

          Object actParsed = MiniJson.parse(actJson);
          if (!(actParsed instanceof Map)) throw new Exception("act_json must be object");
          @SuppressWarnings("unchecked") Map<String,Object> actObj=(Map<String,Object>)actParsed;
          String canonical = canonicalJsonSorted(actObj);
          String actHash = computeActHash(canonical);

          String nonce = UUID.randomUUID().toString();
          String tok = mintConsent(consentKeys, cfg.consentAudience, cfg.consentTtlSeconds, nonce, actHash);
          audit.append("DEV_CONSENT_MINT", "ok");
          json(ex,200,Map.of("consent_token",tok,"nonce",nonce,"act_hash",actHash,"canonical_act_json",canonical));
        } catch (Exception e) {
          String ref = audit.append("DEV_CONSENT_MINT_DENY", e.getMessage());
          json(ex,400,Map.of("error",e.getMessage(),"audit_ref",ref));
        }
      };
    }

    HttpHandler devCapMint() {
      return ex -> {
        if (!cfg.enableDevMint) { json(ex,404,Map.of("error","not found")); return; }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { json(ex,405,Map.of("error","method not allowed")); return; }
        try {
          byte[] body = cif.readChecked(ex);
          Object parsed = MiniJson.parse(new String(body, StandardCharsets.UTF_8));
          if (!(parsed instanceof Map)) throw new Exception("bad json");
          @SuppressWarnings("unchecked") Map<String,Object> m=(Map<String,Object>)parsed;

          Object scopesO = m.get("scopes");
          if (!(scopesO instanceof List)) throw new Exception("missing scopes");
          @SuppressWarnings("unchecked") List<Object> raw=(List<Object>)scopesO;
          List<String> scopes = new ArrayList<>();
          for (Object x : raw) if (x instanceof String) scopes.add((String)x);
          if (scopes.isEmpty()) throw new Exception("empty scopes");

          long exp = Instant.now().getEpochSecond() + cfg.capTtlSeconds;
          Map<String,Object> payload = new LinkedHashMap<>();
          payload.put("v",1);
          payload.put("kid", capKeys.kid);
          payload.put("aud", cfg.capAudience);
          payload.put("exp", exp);
          payload.put("scopes", scopes);

          String json = canonicalJsonSorted(payload);
          byte[] sig = capKeys.sign(json.getBytes(StandardCharsets.UTF_8));
          String tok = SigBox.b64url(json.getBytes(StandardCharsets.UTF_8)) + "." + SigBox.b64url(sig);
          audit.append("DEV_CAP_MINT", scopes.toString());
          json(ex,200,Map.of("cap_token",tok,"exp",exp));
        } catch (Exception e) {
          String ref = audit.append("DEV_CAP_MINT_DENY", e.getMessage());
          json(ex,400,Map.of("error",e.getMessage(),"audit_ref",ref));
        }
      };
    }
  }

  // ------------------------- Main -------------------------
  public static void main(String[] args) throws Exception {
    App app = new App();

    HttpServer server = HttpServer.create(new InetSocketAddress(app.cfg.host, app.cfg.port), 0);
    server.createContext("/healthz", app.healthz());
    server.createContext("/v1/audit/tail", app.auditTail());
    server.createContext("/v1/ask", app.ask());
    server.createContext("/v1/tool/run", app.toolRun());
    server.createContext("/v1/dev/consent/mint", app.devConsentMint());
    server.createContext("/v1/dev/cap/mint", app.devCapMint());

    server.setExecutor(new ThreadPoolExecutor(
        4, 8, 60, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(128),
        new ThreadPoolExecutor.AbortPolicy()
    ));

    System.out.println("OI runtime (hardened) listening on http://" + app.cfg.host + ":" + app.cfg.port);
    System.out.println("CCC enforced: consent (nonce+act_hash) + cap scope + audit");
    System.out.println("Dev mint endpoints enabled? " + app.cfg.enableDevMint);
    server.start();
  }
}
