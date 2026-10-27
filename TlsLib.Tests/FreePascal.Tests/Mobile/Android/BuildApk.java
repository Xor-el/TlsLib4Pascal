import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Packages libTlsLibAndroidTests.so and the Java host into a signed APK (arm64-v8a only).
 * Run from TlsLib.Tests/FreePascal.Tests (or pass --project-dir): java Mobile/Android/BuildApk.java
 * Options (each falls back to the environment): --jdk (JAVA_HOME), --build-tools (ANDROID_BUILD_TOOLS,
 * else the newest under ANDROID_HOME), --android-jar and --strip (ANDROID_HOME, ANDROID_NDK_ROOT),
 * --keystore (TLSLIB_ANDROID_KEYSTORE), --version-code, --install, --target-os (not android: do nothing).
 */
public final class BuildApk {
    private static final String Library = "libTlsLibAndroidTests.so";
    private static final String DebugPassword = "android";
    private static final List<String> Known = List.of("jdk", "build-tools", "android-jar", "strip", "keystore",
        "version-code", "install", "target-os", "project-dir");

    private final boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
    private final Map<String, String> env = System.getenv();
    private final Map<String, String> options = new java.util.HashMap<>();
    private Path projectDir;
    private Path hostDir;
    private Path build;

    public static void main(String[] args) {
        try {
            new BuildApk().run(args);
        } catch (Exception e) {
            System.err.println("build-apk: " + (e.getMessage() == null ? e.toString() : e.getMessage()));
            System.exit(1);
        }
    }

    private void run(String[] args) throws Exception {
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--")) {
                throw new IllegalArgumentException("unexpected argument " + args[i]);
            }
            String name = args[i].substring(2);
            if (!Known.contains(name)) {
                throw new IllegalArgumentException("unknown option " + args[i]);
            }
            options.put(name, name.equals("install") ? "true" : value(args, ++i));
        }
        if (!options.getOrDefault("target-os", "android").equals("android")) {
            return;
        }

        projectDir = Paths.get(options.getOrDefault("project-dir", ".")).toAbsolutePath().normalize();
        hostDir = projectDir.resolve("Mobile").resolve("Android");
        if (!Files.exists(hostDir.resolve("AndroidManifest.xml"))) {
            throw new IllegalStateException("run from TlsLib.Tests/FreePascal.Tests or pass --project-dir; no "
                + hostDir.resolve("AndroidManifest.xml"));
        }
        build = hostDir.resolve("build");

        Path jdk = jdk();
        Path sdk = sdk();
        Path buildTools = buildTools(sdk);
        Path androidJar = androidJar(sdk);
        Path strip = strip(sdk);
        Path keystore = keystore();
        Path library = projectDir.resolve("bin").resolve(Library);
        Path dataRoot = projectDir.getParent().resolve("Data");
        require(library, "the library was not found; build it first");
        require(dataRoot, "the test data folder was not found");

        deleteTree(build);
        Path classes = Files.createDirectories(build.resolve("classes"));
        Path dex = Files.createDirectories(build.resolve("dex"));
        Path assets = Files.createDirectories(build.resolve("assets"));
        Path libFolder = Files.createDirectories(build.resolve("lib").resolve("arm64-v8a"));

        // the test data goes in as one archive; the app unpacks it to TlsLib.Tests/Data on the phone
        zipTestData(dataRoot, assets.resolve("testdata.zip"));
        Path stripped = libFolder.resolve(Library);
        exec(strip.toString(), "--strip-unneeded", "-o", stripped.toString(), library.toString());

        List<String> javac = new ArrayList<>(List.of(tool(jdk.resolve("bin"), "javac").toString(),
            "--release", "8", "-Xlint:-options", "-cp", androidJar.toString(), "-d", classes.toString()));
        try (Stream<Path> sources = Files.walk(hostDir.resolve("src"))) {
            sources.filter(p -> p.toString().endsWith(".java")).forEach(p -> javac.add(p.toString()));
        }
        exec(javac);

        List<String> d8 = new ArrayList<>(List.of(java(jdk), "-cp", buildTools.resolve("lib").resolve("d8.jar").toString(),
            "com.android.tools.r8.D8", "--lib", androidJar.toString(), "--min-api", "24", "--output", dex.toString()));
        try (Stream<Path> files = Files.walk(classes)) {
            files.filter(p -> p.toString().endsWith(".class")).forEach(p -> d8.add(p.toString()));
        }
        exec(d8);

        int versionCode = options.containsKey("version-code") ? Integer.parseInt(options.get("version-code"))
            : (int) Duration.between(Instant.parse("2026-01-01T00:00:00Z"), Instant.now()).toMinutes();
        Path unsigned = build.resolve("unsigned.apk");
        exec(tool(buildTools, "aapt2").toString(), "link", "-o", unsigned.toString(),
            "--manifest", hostDir.resolve("AndroidManifest.xml").toString(), "-I", androidJar.toString(),
            "-A", assets.toString(), "--min-sdk-version", "24", "--target-sdk-version", "35",
            "--version-code", String.valueOf(versionCode), "--version-name", "1." + versionCode);

        addToZip(unsigned, "classes.dex", dex.resolve("classes.dex"));
        addToZip(unsigned, "lib/arm64-v8a/" + Library, stripped);

        Path aligned = build.resolve("aligned.apk");
        exec(tool(buildTools, "zipalign").toString(), "-f", "-p", "4", unsigned.toString(), aligned.toString());

        if (!Files.exists(keystore)) {
            Files.createDirectories(keystore.getParent());
            exec(tool(jdk.resolve("bin"), "keytool").toString(), "-genkeypair", "-keystore", keystore.toString(),
                "-alias", "tlslibdebug", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                "-storepass", DebugPassword, "-keypass", DebugPassword, "-dname", "CN=TlsLib Tests Debug");
        }
        Path apk = build.resolve("TlsLibTests.apk");
        List<String> sign = apksigner(jdk, buildTools);
        sign.addAll(List.of("sign", "--ks", keystore.toString(), "--ks-pass", "pass:" + DebugPassword,
            "--key-pass", "pass:" + DebugPassword, "--out", apk.toString(), aligned.toString()));
        exec(sign);
        List<String> verify = apksigner(jdk, buildTools);
        verify.addAll(List.of("verify", "--verbose", apk.toString()));
        exec(verify);

        System.out.println(apk + " " + Files.size(apk) + " bytes");

        if (options.containsKey("install")) {
            Path adb = sdk == null ? null : sdk.resolve("platform-tools").resolve(windows ? "adb.exe" : "adb");
            exec(adb != null && Files.exists(adb) ? adb.toString() : "adb", "install", "-r", apk.toString());
        }
    }

    private static String value(String[] args, int index) {
        if (index >= args.length) {
            throw new IllegalArgumentException("missing value for " + args[index - 1]);
        }
        return args[index];
    }

    private String setting(String option, String environment) {
        String fromOption = options.get(option);
        if (fromOption != null && !fromOption.isEmpty()) {
            return fromOption;
        }
        String fromEnv = environment == null ? null : env.get(environment);
        return fromEnv == null || fromEnv.isEmpty() ? null : fromEnv;
    }

    private Path jdk() {
        String given = setting("jdk", "JAVA_HOME");
        Path jdk = Paths.get(given != null ? given : System.getProperty("java.home"));
        require(tool(jdk.resolve("bin"), "javac"), "javac was not found in the JDK; pass --jdk or set JAVA_HOME");
        return jdk;
    }

    private Path sdk() {
        for (String name : List.of("ANDROID_HOME", "ANDROID_SDK_ROOT")) {
            String given = env.get(name);
            if (given != null && !given.isEmpty()) {
                return Paths.get(given);
            }
        }
        return null;
    }

    private Path buildTools(Path sdk) {
        String given = setting("build-tools", "ANDROID_BUILD_TOOLS");
        Path folder = given != null ? Paths.get(given) : newest(sdk == null ? null : sdk.resolve("build-tools"), null);
        return require(folder, "no build-tools folder; pass --build-tools, or set ANDROID_BUILD_TOOLS or ANDROID_HOME");
    }

    private Path androidJar(Path sdk) {
        String given = setting("android-jar", null);
        Path jar = given != null ? Paths.get(given) : null;
        if (jar == null && sdk != null) {
            Path platform = newest(sdk.resolve("platforms"), "android.jar");
            jar = platform == null ? null : platform.resolve("android.jar");
        }
        return require(jar, "no android.jar; pass --android-jar, or set ANDROID_HOME to an SDK with a platform installed");
    }

    private Path strip(Path sdk) {
        String given = setting("strip", null);
        if (given != null) {
            return require(Paths.get(given), "llvm-strip was not found");
        }
        String ndkRoot = env.get("ANDROID_NDK_ROOT");
        Path ndk = ndkRoot != null && !ndkRoot.isEmpty() ? Paths.get(ndkRoot)
            : newest(sdk == null ? null : sdk.resolve("ndk"), null);
        Path strip = ndk == null ? null : tool(ndk.resolve("toolchains").resolve("llvm").resolve("prebuilt")
            .resolve(hostTag()).resolve("bin"), "llvm-strip");
        return require(strip, "no llvm-strip; pass --strip, or set ANDROID_NDK_ROOT (or ANDROID_HOME with an ndk folder)");
    }

    private Path keystore() {
        String given = setting("keystore", "TLSLIB_ANDROID_KEYSTORE");
        return given != null ? Paths.get(given)
            : Paths.get(System.getProperty("user.home"), ".android", "tlslib-debug.keystore");
    }

    // the NDK ships one prebuilt folder per host; macOS has a single one for both CPUs
    private String hostTag() {
        String os = System.getProperty("os.name").toLowerCase();
        if (windows) {
            return "windows-x86_64";
        }
        return os.contains("mac") ? "darwin-x86_64" : "linux-x86_64";
    }

    private Path tool(Path folder, String name) {
        return folder.resolve(windows ? name + ".exe" : name);
    }

    private String java(Path jdk) {
        return tool(jdk.resolve("bin"), "java").toString();
    }

    private List<String> apksigner(Path jdk, Path buildTools) {
        return new ArrayList<>(List.of(java(jdk), "-jar", buildTools.resolve("lib").resolve("apksigner.jar").toString()));
    }

    /** The folder under parent with the highest version in its name; one holding the given file if named. */
    private static Path newest(Path parent, String mustContain) {
        if (parent == null || !Files.isDirectory(parent)) {
            return null;
        }
        try (Stream<Path> folders = Files.list(parent)) {
            return folders.filter(Files::isDirectory)
                .filter(p -> mustContain == null || Files.exists(p.resolve(mustContain)))
                .max(Comparator.comparing(p -> numbers(p.getFileName().toString()), BuildApk::compareNumbers))
                .orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    private static List<Integer> numbers(String text) {
        List<Integer> result = new ArrayList<>();
        Matcher matcher = Pattern.compile("\\d+").matcher(text);
        while (matcher.find()) {
            result.add(Integer.parseInt(matcher.group()));
        }
        return result;
    }

    private static int compareNumbers(List<Integer> left, List<Integer> right) {
        for (int i = 0; i < Math.min(left.size(), right.size()); i++) {
            int order = Integer.compare(left.get(i), right.get(i));
            if (order != 0) {
                return order;
            }
        }
        return Integer.compare(left.size(), right.size());
    }

    private static Path require(Path path, String what) {
        if (path == null || !Files.exists(path)) {
            throw new IllegalStateException(what + (path == null ? "" : " (looked at " + path + ")"));
        }
        return path;
    }

    private static void zipTestData(Path dataRoot, Path target) throws IOException {
        Path testsRoot = dataRoot.getParent();
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target));
             Stream<Path> files = Files.walk(dataRoot)) {
            for (Path file : files.filter(Files::isRegularFile).collect(Collectors.toList())) {
                String name = "TlsLib.Tests/" + testsRoot.relativize(file).toString().replace('\\', '/');
                zip.putNextEntry(new ZipEntry(name));
                Files.copy(file, zip);
                zip.closeEntry();
            }
        }
    }

    private static void addToZip(Path zip, String entry, Path file) throws IOException {
        try (FileSystem fs = FileSystems.newFileSystem(zip)) {
            Path inside = fs.getPath(entry);
            if (inside.getParent() != null) {
                Files.createDirectories(inside.getParent());
            }
            Files.copy(file, inside, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteTree(Path folder) throws IOException {
        if (!Files.exists(folder)) {
            return;
        }
        try (Stream<Path> files = Files.walk(folder)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                Files.delete(file);
            }
        }
    }

    private static void exec(String... command) throws IOException, InterruptedException {
        exec(new ArrayList<>(List.of(command)));
    }

    // a tool's stderr is not an error in itself; the exit code decides
    private static void exec(List<String> command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).inheritIO().start();
        int code = process.waitFor();
        if (code != 0) {
            throw new IllegalStateException("failed (" + code + "): " + String.join(" ", command));
        }
    }
}
