package org.angrycli.bridge;

import net.azib.ipscan.config.ComponentRegistry;
import net.azib.ipscan.config.Config;
import net.azib.ipscan.config.Labels;
import net.azib.ipscan.config.Platform;
import net.azib.ipscan.config.ScannerConfig;
import net.azib.ipscan.config.Version;
import net.azib.ipscan.core.PortIterator;
import net.azib.ipscan.core.Scanner;
import net.azib.ipscan.core.ScannerDispatcherThread;
import net.azib.ipscan.core.ScanningProgressCallback;
import net.azib.ipscan.core.ScanningResult;
import net.azib.ipscan.core.ScanningResult.ResultType;
import net.azib.ipscan.core.ScanningResultCallback;
import net.azib.ipscan.core.ScanningResultList;
import net.azib.ipscan.core.net.PingerRegistry;
import net.azib.ipscan.core.state.ScanningState;
import net.azib.ipscan.core.state.StateMachine;
import net.azib.ipscan.core.values.NotAvailable;
import net.azib.ipscan.core.values.NotScanned;
import net.azib.ipscan.core.values.NumericRangeList;
import net.azib.ipscan.di.Injector;
import net.azib.ipscan.exporters.ExportProcessor;
import net.azib.ipscan.exporters.Exporter;
import net.azib.ipscan.exporters.ExporterRegistry;
import net.azib.ipscan.feeders.Feeder;
import net.azib.ipscan.feeders.FileFeeder;
import net.azib.ipscan.feeders.RandomFeeder;
import net.azib.ipscan.feeders.RangeFeeder;
import net.azib.ipscan.feeders.RescanFeeder;
import net.azib.ipscan.fetchers.Fetcher;
import net.azib.ipscan.fetchers.FetcherRegistry;
import net.azib.ipscan.fetchers.IPFetcher;
import net.azib.ipscan.fetchers.PortsFetcher;

import java.io.File;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.prefs.Preferences;

/**
 * Headless Java bridge for angry-cli (ipscan).
 *
 * Directly invokes Angry IP Scanner's real DI container, Pingers, Fetchers,
 * Feeders, ScannerDispatcherThread, and Exporters without initializing SWT GUI.
 *
 * Commands:
 *   info                     - Inspect real Angry IP Scanner capabilities
 *   scan <request.json>      - Execute a real scan and optionally export results
 *   export <request.json>    - Export saved scan results via real Angry IP Scanner Exporters
 */
public class HeadlessBridge {

    static class HeadlessStateMachine extends StateMachine {
    }

    public static void main(String[] args) {
        try {
            silenceJavaLogging();
            disableDnsCache();

            if (args.length == 0) {
                emitError("Usage: HeadlessBridge <info|scan|export> [request.json]");
                System.exit(2);
            }

            String action = args[0];
            switch (action) {
                case "info":
                    handleInfo();
                    break;
                case "scan":
                    if (args.length < 2) {
                        emitError("scan requires a request JSON file path");
                        System.exit(2);
                    }
                    handleScan(Path.of(args[1]));
                    break;
                case "export":
                    if (args.length < 2) {
                        emitError("export requires a request JSON file path");
                        System.exit(2);
                    }
                    handleExport(Path.of(args[1]));
                    break;
                default:
                    emitError("Unknown bridge action: " + action);
                    System.exit(2);
            }
        }
        catch (Throwable t) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("ok", false);
            err.put("error", t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName());
            err.put("exception", t.getClass().getName());
            System.out.println(JsonCodec.stringify(err));
            System.exit(1);
        }
    }

    private static void silenceJavaLogging() {
        Logger root = LogManager.getLogManager().getLogger("");
        if (root != null) {
            root.setLevel(Level.OFF);
            for (var h : root.getHandlers()) {
                h.setLevel(Level.OFF);
            }
        }
    }

    private static void disableDnsCache() {
        Security.setProperty("networkaddress.cache.ttl", "0");
        Security.setProperty("networkaddress.cache.negative.ttl", "0");
    }

    private static Injector bootstrapHeadless(Map<String, Object> request) throws Exception {
        Labels.initialize(Locale.ENGLISH);

        Preferences prefs = Preferences.userRoot().node("ipscan");
        if (request != null) {
            applyPreferencesFromRequest(prefs, request);
        }

        Injector injector = new ComponentRegistry().init(false);
        StateMachine stateMachine = new HeadlessStateMachine();
        injector.register(StateMachine.class, stateMachine);

        List<Fetcher> allFetchers = injector.requireAll(Fetcher.class);
        FetcherRegistry fetcherRegistry = new FetcherRegistry(allFetchers, prefs, null);
        injector.register(FetcherRegistry.class, fetcherRegistry);

        ScanningResultList resultList = new ScanningResultList(fetcherRegistry, stateMachine);
        injector.register(ScanningResultList.class, resultList);

        Scanner scanner = new Scanner(fetcherRegistry);
        injector.register(Scanner.class, scanner);

        // Ensure PingerRegistry & ExporterRegistry are initialized
        injector.require(PingerRegistry.class);
        injector.require(ExporterRegistry.class);
        return injector;
    }

    @SuppressWarnings("unchecked")
    private static void applyPreferencesFromRequest(Preferences prefs, Map<String, Object> request) {
        Object cfgObj = request.get("scanner_config");
        if (cfgObj instanceof Map) {
            Map<String, Object> cfg = (Map<String, Object>) cfgObj;
            putIntIfPresent(prefs, "maxThreads", cfg.get("max_threads"));
            putIntIfPresent(prefs, "threadDelay", cfg.get("thread_delay"));
            putBoolIfPresent(prefs, "scanDeadHosts", cfg.get("scan_dead_hosts"));
            putStrIfPresent(prefs, "selectedPinger", cfg.get("selected_pinger"));
            putIntIfPresent(prefs, "pingTimeout", cfg.get("ping_timeout"));
            putIntIfPresent(prefs, "pingCount", cfg.get("ping_count"));
            putBoolIfPresent(prefs, "skipBroadcastAddresses", cfg.get("skip_broadcast_addresses"));
            putIntIfPresent(prefs, "portTimeout", cfg.get("port_timeout"));
            putBoolIfPresent(prefs, "adaptPortTimeout", cfg.get("adapt_port_timeout"));
            putIntIfPresent(prefs, "minPortTimeout", cfg.get("min_port_timeout"));
            putStrIfPresent(prefs, "portString", cfg.get("port_string"));
            putBoolIfPresent(prefs, "useRequestedPorts", cfg.get("use_requested_ports"));
            putStrIfPresent(prefs, "notAvailableText", cfg.get("not_available_text"));
            putStrIfPresent(prefs, "notScannedText", cfg.get("not_scanned_text"));
        }

        Object selObj = request.get("selected_fetchers");
        if (selObj instanceof List) {
            List<?> sel = (List<?>) selObj;
            if (!sel.isEmpty()) {
                List<String> ids = new ArrayList<>();
                for (Object item : sel) {
                    if (item != null) {
                        ids.add(item.toString());
                    }
                }
                if (!ids.isEmpty()) {
                    prefs.put("selectedFetchers", String.join("###", ids));
                }
            }
        }

        Object fpObj = request.get("fetcher_prefs");
        if (fpObj instanceof Map) {
            Map<String, Object> fp = (Map<String, Object>) fpObj;
            for (var entry : fp.entrySet()) {
                if (entry.getValue() instanceof Map) {
                    Preferences node = prefs.node(entry.getKey());
                    Map<String, Object> sub = (Map<String, Object>) entry.getValue();
                    for (var kv : sub.entrySet()) {
                        if (kv.getValue() != null) {
                            node.put(kv.getKey(), kv.getValue().toString());
                        }
                    }
                }
            }
        }

        Object commentsObj = request.get("comments");
        if (commentsObj instanceof Map) {
            Preferences commentsNode = prefs.node("comments");
            Map<String, Object> comments = (Map<String, Object>) commentsObj;
            for (var entry : comments.entrySet()) {
                if (entry.getValue() != null && !entry.getValue().toString().isEmpty()) {
                    commentsNode.put(entry.getKey(), entry.getValue().toString());
                }
            }
        }
    }

    private static void putIntIfPresent(Preferences prefs, String key, Object val) {
        if (val instanceof Number) {
            prefs.putInt(key, ((Number) val).intValue());
        }
    }

    private static void putBoolIfPresent(Preferences prefs, String key, Object val) {
        if (val instanceof Boolean) {
            prefs.putBoolean(key, (Boolean) val);
        }
    }

    private static void putStrIfPresent(Preferences prefs, String key, Object val) {
        if (val instanceof String) {
            prefs.put(key, (String) val);
        }
    }

    private static void handleInfo() throws Exception {
        Injector injector = bootstrapHeadless(null);
        FetcherRegistry fetcherRegistry = injector.require(FetcherRegistry.class);
        PingerRegistry pingerRegistry = injector.require(PingerRegistry.class);
        ExporterRegistry exporterRegistry = injector.require(ExporterRegistry.class);
        ScannerConfig scannerConfig = injector.require(ScannerConfig.class);

        String ver = Version.getVersion();
        String fullName = ver != null ? Version.getFullName() : (Version.NAME + " (source build)");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("version", ver != null ? ver : "source");
        out.put("full_name", fullName);
        out.put("website", Version.WEBSITE);

        Map<String, Object> platform = new LinkedHashMap<>();
        platform.put("os_name", System.getProperty("os.name"));
        platform.put("os_arch", System.getProperty("os.arch"));
        platform.put("java_version", System.getProperty("java.version"));
        platform.put("windows", Platform.WINDOWS);
        platform.put("linux", Platform.LINUX);
        platform.put("mac_os", Platform.MAC_OS);
        out.put("platform", platform);

        List<Map<String, Object>> pingers = new ArrayList<>();
        for (String pid : pingerRegistry.getRegisteredNames()) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("id", pid);
            p.put("name", safeLabel(pid));
            p.put("default", pid.equals(scannerConfig.selectedPinger));
            pingers.add(p);
        }
        out.put("pingers", pingers);

        List<String> defaultSelectedIds = new ArrayList<>();
        for (Fetcher f : fetcherRegistry.getSelectedFetchers()) {
            defaultSelectedIds.add(f.getId());
        }

        List<Map<String, Object>> fetchers = new ArrayList<>();
        for (Fetcher f : fetcherRegistry.getRegisteredFetchers()) {
            Map<String, Object> fm = new LinkedHashMap<>();
            fm.put("id", f.getId());
            fm.put("name", f.getName());
            fm.put("full_name", f.getFullName());
            fm.put("info", f.getInfo());
            fm.put("default_selected", defaultSelectedIds.contains(f.getId()));
            fetchers.add(fm);
        }
        out.put("fetchers", fetchers);

        List<Map<String, Object>> exporters = new ArrayList<>();
        for (Exporter e : exporterRegistry) {
            Map<String, Object> em = new LinkedHashMap<>();
            em.put("id", e.getId());
            em.put("extension", e.getFilenameExtension());
            em.put("name", safeLabel(e.getId()));
            exporters.add(em);
        }
        out.put("exporters", exporters);

        System.out.println(JsonCodec.stringify(out));
    }

    @SuppressWarnings("unchecked")
    private static void handleScan(Path requestPath) throws Exception {
        String raw = Files.readString(requestPath, StandardCharsets.UTF_8);
        Map<String, Object> request = (Map<String, Object>) JsonCodec.parse(raw);

        Injector injector = bootstrapHeadless(request);
        StateMachine stateMachine = injector.require(StateMachine.class);
        FetcherRegistry fetcherRegistry = injector.require(FetcherRegistry.class);
        ScanningResultList resultList = injector.require(ScanningResultList.class);
        Scanner scanner = injector.require(Scanner.class);
        ScannerConfig scannerConfig = injector.require(ScannerConfig.class);
        ExporterRegistry exporterRegistry = injector.require(ExporterRegistry.class);

        Map<String, Object> target = (Map<String, Object>) request.get("target");
        if (target == null) {
            throw new IllegalArgumentException("Missing 'target' in scan request");
        }
        Feeder feeder = buildFeeder(target);

        CountDownLatch completionLatch = new CountDownLatch(1);
        stateMachine.addTransitionListener((state, transition) -> {
            if (transition == StateMachine.Transition.COMPLETE && state == ScanningState.IDLE) {
                completionLatch.countDown();
            }
        });

        AtomicInteger rowCounter = new AtomicInteger(0);
        ScanningResultCallback resultCallback = new ScanningResultCallback() {
            @Override
            public void prepareForResults(ScanningResult result) {
                synchronized (resultList) {
                    if (!resultList.isRegistered(result)) {
                        resultList.registerAtIndex(rowCounter.getAndIncrement(), result);
                    }
                }
            }

            @Override
            public void fetcherCompleted(ScanningResult result) {
                resultList.update(result);
            }

            @Override
            public void consumeResults(ScanningResult result) {
                resultList.update(result);
            }
        };

        ScanningProgressCallback progressCallback = (addr, running, pct) -> {
            // quiet headless progress
        };

        stateMachine.init();
        stateMachine.transitionToNext(); // IDLE -> STARTING
        ScannerDispatcherThread dispatcher = new ScannerDispatcherThread(
                feeder, scanner, stateMachine, progressCallback, resultList, scannerConfig, resultCallback
        );
        stateMachine.startScanning(); // STARTING -> SCANNING
        dispatcher.start();
        dispatcher.join();
        completionLatch.await();

        // Optional direct export using real Angry IP Scanner Exporter
        Map<String, Object> exportInfo = null;
        Object exportObj = request.get("export");
        if (exportObj instanceof Map) {
            exportInfo = runNativeExport(exporterRegistry, resultList, (Map<String, Object>) exportObj);
        }

        // Serialize scan output
        List<Fetcher> usedFetchers = resultList.getFetchers();
        List<Map<String, Object>> fetcherMeta = new ArrayList<>();
        for (Fetcher f : usedFetchers) {
            Map<String, Object> fm = new LinkedHashMap<>();
            fm.put("id", f.getId());
            fm.put("name", f.getName());
            fm.put("full_name", f.getFullName());
            fetcherMeta.add(fm);
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        for (ScanningResult sr : resultList) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ip", sr.getAddress().getHostAddress());
            row.put("type", sr.getType().name());
            row.put("mac", sr.getMac());
            Map<String, Object> valuesMap = new LinkedHashMap<>();
            List<Object> vals = sr.getValues();
            for (int i = 0; i < usedFetchers.size() && i < vals.size(); i++) {
                Fetcher f = usedFetchers.get(i);
                Object v = vals.get(i);
                valuesMap.put(f.getId(), serializeFetcherValue(v, scannerConfig));
            }
            row.put("values", valuesMap);
            rows.add(row);
        }

        ScanningResultList.ScanInfo info = resultList.getScanInfo();
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("host_count", info != null ? info.getHostCount() : rows.size());
        stats.put("alive_count", info != null ? info.getAliveCount() : 0);
        stats.put("with_ports_count", info != null ? info.getWithPortsCount() : 0);
        stats.put("dead_count", Math.max(0, (info != null ? info.getHostCount() : rows.size()) - (info != null ? info.getAliveCount() : 0)));
        stats.put("scan_time_ms", info != null ? info.getScanTime() : 0);
        stats.put("completed_normally", info != null && info.isCompletedNormally());

        String engineName = Version.getVersion() != null ? Version.getFullName() : (Version.NAME + " (source build)");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("engine", engineName);
        out.put("feeder_name", resultList.getFeederName());
        out.put("feeder_info", resultList.getFeederInfo());
        out.put("pinger", scannerConfig.selectedPinger);
        out.put("fetchers", fetcherMeta);
        out.put("stats", stats);
        out.put("results", rows);
        if (exportInfo != null) {
            out.put("export", exportInfo);
        }

        System.out.println(JsonCodec.stringify(out));
    }

    @SuppressWarnings("unchecked")
    private static void handleExport(Path requestPath) throws Exception {
        String raw = Files.readString(requestPath, StandardCharsets.UTF_8);
        Map<String, Object> request = (Map<String, Object>) JsonCodec.parse(raw);

        Injector injector = bootstrapHeadless(request);
        FetcherRegistry fetcherRegistry = injector.require(FetcherRegistry.class);
        ExporterRegistry exporterRegistry = injector.require(ExporterRegistry.class);
        ScanningResultList resultList = new ScanningResultList(fetcherRegistry);

        String feederName = request.get("feeder_name") != null ? request.get("feeder_name").toString() : "IP Range";
        String feederInfo = request.get("feeder_info") != null ? request.get("feeder_info").toString() : "CLI Export";

        // Minimal feeder stub solely to supply feederName & feederInfo to ScanningResultList.initNewScan
        Feeder metadataFeeder = new Feeder() {
            @Override public String getId() { return "feeder.range"; }
            @Override public String getName() { return feederName; }
            @Override public boolean hasNext() { return false; }
            @Override public net.azib.ipscan.core.ScanningSubject next() { return null; }
            @Override public int percentageComplete() { return 100; }
            @Override public String getInfo() { return feederInfo; }
            @Override public boolean isLocalNetwork() { return false; }
        };
        resultList.initNewScan(metadataFeeder);

        List<Fetcher> selectedFetchers = resultList.getFetchers();
        List<Map<String, Object>> inputRows = (List<Map<String, Object>>) request.get("results");
        if (inputRows == null) {
            inputRows = List.of();
        }

        int idx = 0;
        for (Map<String, Object> row : inputRows) {
            String ipStr = row.get("ip").toString();
            InetAddress addr = InetAddress.getByName(ipStr);
            ScanningResult sr = new ScanningResult(addr, selectedFetchers.size());

            String typeStr = row.get("type") != null ? row.get("type").toString() : "UNKNOWN";
            try {
                sr.setType(ResultType.valueOf(typeStr));
            }
            catch (IllegalArgumentException e) {
                sr.setType(ResultType.UNKNOWN);
            }

            if (row.get("mac") != null) {
                sr.setMac(row.get("mac").toString());
            }

            Map<String, Object> vals = (Map<String, Object>) row.get("values");
            for (int i = 0; i < selectedFetchers.size(); i++) {
                Fetcher f = selectedFetchers.get(i);
                Object rawVal = vals != null ? vals.get(f.getId()) : null;
                sr.setValue(i, reconstructFetcherValue(f.getId(), rawVal, ipStr));
            }
            resultList.registerAtIndex(idx++, sr);
        }

        Map<String, Object> exportSpec = (Map<String, Object>) request.get("export");
        if (exportSpec == null) {
            throw new IllegalArgumentException("Missing 'export' specification");
        }
        Map<String, Object> exportInfo = runNativeExport(exporterRegistry, resultList, exportSpec);

        String engineName = Version.getVersion() != null ? Version.getFullName() : (Version.NAME + " (source build)");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("engine", engineName);
        out.put("export", exportInfo);
        System.out.println(JsonCodec.stringify(out));
    }

    private static Map<String, Object> runNativeExport(
            ExporterRegistry exporterRegistry,
            ScanningResultList resultList,
            Map<String, Object> exportSpec
    ) {
        String outputPath = exportSpec.get("output_path").toString();
        boolean append = Boolean.TRUE.equals(exportSpec.get("append"));
        String filterMode = exportSpec.get("filter") != null ? exportSpec.get("filter").toString().toLowerCase(Locale.ROOT) : "all";

        File outFile = new File(outputPath);
        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        Exporter exporter = exporterRegistry.createExporter(outputPath);
        ExportProcessor.ScanningResultFilter filter = null;
        if ("alive".equals(filterMode)) {
            filter = (index, res) -> res.getType() == ResultType.ALIVE || res.getType() == ResultType.WITH_PORTS;
        }
        else if ("ports".equals(filterMode) || "with_ports".equals(filterMode)) {
            filter = (index, res) -> res.getType() == ResultType.WITH_PORTS;
        }
        else if ("dead".equals(filterMode)) {
            filter = (index, res) -> res.getType() == ResultType.DEAD || res.getType() == ResultType.UNKNOWN;
        }

        int exportedRows = 0;
        for (ScanningResult sr : resultList) {
            if (filter == null || filter.apply(exportedRows, sr)) {
                exportedRows++;
            }
        }

        ExportProcessor processor = new ExportProcessor(exporter, outFile, append);
        processor.process(resultList, filter);

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("output_path", outFile.getAbsolutePath());
        info.put("exporter_id", exporter.getId());
        info.put("format", exporter.getFilenameExtension());
        info.put("append", append);
        info.put("filter", filterMode);
        info.put("exported_rows", exportedRows);
        info.put("file_size", outFile.length());
        return info;
    }

    @SuppressWarnings("unchecked")
    private static Feeder buildFeeder(Map<String, Object> target) {
        String kind = target.get("feeder") != null ? target.get("feeder").toString().toLowerCase(Locale.ROOT) : "range";
        switch (kind) {
            case "range": {
                String startIp = requireStr(target, "start_ip");
                String endIp = requireStr(target, "end_ip");
                return new RangeFeeder(startIp, endIp);
            }
            case "random": {
                String baseIp = requireStr(target, "base_ip");
                String mask = requireStr(target, "mask");
                Object countObj = target.get("count");
                int count = countObj instanceof Number ? ((Number) countObj).intValue() : Integer.parseInt(countObj.toString());
                return new RandomFeeder(baseIp, mask, count);
            }
            case "file": {
                String filePath = requireStr(target, "file_path");
                return new FileFeeder(filePath);
            }
            case "rescan": {
                List<?> ipsObj = (List<?>) target.get("ips");
                if (ipsObj == null || ipsObj.isEmpty()) {
                    throw new IllegalArgumentException("rescan feeder requires non-empty 'ips' list");
                }
                String[] ips = new String[ipsObj.size()];
                for (int i = 0; i < ipsObj.size(); i++) {
                    ips[i] = ipsObj.get(i).toString();
                }
                RangeFeeder base = new RangeFeeder(ips[0], ips[ips.length - 1]);
                return new RescanFeeder(base, ips);
            }
            default:
                throw new IllegalArgumentException("Unsupported feeder type: " + kind);
        }
    }

    private static String requireStr(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v == null || v.toString().isEmpty()) {
            throw new IllegalArgumentException("Missing required field: " + key);
        }
        return v.toString();
    }

    private static Object serializeFetcherValue(Object value, ScannerConfig cfg) {
        if (value == null) return null;
        if (value == NotAvailable.VALUE) return cfg.notAvailableText;
        if (value == NotScanned.VALUE) return cfg.notScannedText;
        return value.toString().replace('\u00a0', ' ');
    }

    private static Object reconstructFetcherValue(String fetcherId, Object rawVal, String ipStr) {
        if (rawVal == null) {
            return IPFetcher.ID.equals(fetcherId) ? ipStr : NotAvailable.VALUE;
        }
        String text = rawVal.toString();
        if (PortsFetcher.ID.equals(fetcherId) || "fetcher.ports.filtered".equals(fetcherId)) {
            if (!text.isEmpty() && Character.isDigit(text.charAt(0))) {
                try {
                    List<Integer> ports = new ArrayList<>();
                    for (PortIterator it = new PortIterator(text); it.hasNext(); ) {
                        ports.add(it.next());
                    }
                    if (!ports.isEmpty()) {
                        return new NumericRangeList(ports, true);
                    }
                }
                catch (Exception ignore) {
                    // fall back to string
                }
            }
        }
        return text;
    }

    private static String safeLabel(String key) {
        try {
            String v = Labels.getInstance().getOrNull(key);
            return v != null ? v : key;
        }
        catch (Exception e) {
            return key;
        }
    }

    private static void emitError(String msg) {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("ok", false);
        err.put("error", msg);
        System.out.println(JsonCodec.stringify(err));
    }

    /**
     * Minimal dependency-free RFC 8259 JSON parser and serializer.
     */
    static final class JsonCodec {
        private final String src;
        private int pos;

        private JsonCodec(String src) {
            this.src = src;
        }

        static Object parse(String json) {
            JsonCodec p = new JsonCodec(json);
            p.skipWs();
            Object v = p.parseValue();
            p.skipWs();
            return v;
        }

        static String stringify(Object value) {
            StringBuilder sb = new StringBuilder();
            writeJson(value, sb);
            return sb.toString();
        }

        private static void writeJson(Object v, StringBuilder sb) {
            if (v == null) {
                sb.append("null");
            }
            else if (v instanceof Boolean) {
                sb.append(((Boolean) v) ? "true" : "false");
            }
            else if (v instanceof Number) {
                sb.append(v);
            }
            else if (v instanceof String) {
                writeString((String) v, sb);
            }
            else if (v instanceof Map<?, ?>) {
                sb.append('{');
                boolean first = true;
                for (var e : ((Map<?, ?>) v).entrySet()) {
                    if (!first) sb.append(',');
                    first = false;
                    writeString(String.valueOf(e.getKey()), sb);
                    sb.append(':');
                    writeJson(e.getValue(), sb);
                }
                sb.append('}');
            }
            else if (v instanceof Iterable<?>) {
                sb.append('[');
                boolean first = true;
                for (Object item : (Iterable<?>) v) {
                    if (!first) sb.append(',');
                    first = false;
                    writeJson(item, sb);
                }
                sb.append(']');
            }
            else {
                writeString(v.toString(), sb);
            }
        }

        private static void writeString(String s, StringBuilder sb) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\b': sb.append("\\b"); break;
                    case '\f': sb.append("\\f"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        }
                        else {
                            sb.append(c);
                        }
                }
            }
            sb.append('"');
        }

        private void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') pos++;
                else break;
            }
        }

        private Object parseValue() {
            skipWs();
            if (pos >= src.length()) throw new IllegalArgumentException("Unexpected end of JSON");
            char c = src.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't') { expect("true"); return Boolean.TRUE; }
            if (c == 'f') { expect("false"); return Boolean.FALSE; }
            if (c == 'n') { expect("null"); return null; }
            if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
            throw new IllegalArgumentException("Unexpected char at " + pos + ": " + c);
        }

        private Map<String, Object> parseObject() {
            pos++; // '{'
            Map<String, Object> map = new LinkedHashMap<>();
            skipWs();
            if (pos < src.length() && src.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                if (pos >= src.length() || src.charAt(pos) != ':') {
                    throw new IllegalArgumentException("Expected ':' at " + pos);
                }
                pos++;
                Object val = parseValue();
                map.put(key, val);
                skipWs();
                if (pos >= src.length()) throw new IllegalArgumentException("Unterminated object");
                char sep = src.charAt(pos++);
                if (sep == '}') break;
                if (sep != ',') throw new IllegalArgumentException("Expected ',' or '}' at " + (pos - 1));
            }
            return map;
        }

        private List<Object> parseArray() {
            pos++; // '['
            List<Object> list = new ArrayList<>();
            skipWs();
            if (pos < src.length() && src.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWs();
                if (pos >= src.length()) throw new IllegalArgumentException("Unterminated array");
                char sep = src.charAt(pos++);
                if (sep == ']') break;
                if (sep != ',') throw new IllegalArgumentException("Expected ',' or ']' at " + (pos - 1));
            }
            return list;
        }

        private String parseString() {
            if (src.charAt(pos) != '"') throw new IllegalArgumentException("Expected '\"' at " + pos);
            pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= src.length()) throw new IllegalArgumentException("Unterminated escape");
                    char e = src.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            String hex = src.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("Invalid escape: \\" + e);
                    }
                }
                else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Unterminated string");
        }

        private Number parseNumber() {
            int start = pos;
            if (src.charAt(pos) == '-') pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            boolean isFloat = false;
            if (pos < src.length() && src.charAt(pos) == '.') {
                isFloat = true;
                pos++;
                while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            }
            if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
                isFloat = true;
                pos++;
                if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
                while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            }
            String token = src.substring(start, pos);
            return isFloat ? Double.parseDouble(token) : Long.parseLong(token);
        }

        private void expect(String literal) {
            if (!src.startsWith(literal, pos)) {
                throw new IllegalArgumentException("Expected " + literal + " at " + pos);
            }
            pos += literal.length();
        }
    }
}
