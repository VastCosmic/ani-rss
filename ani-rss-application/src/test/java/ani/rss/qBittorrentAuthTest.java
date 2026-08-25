package ani.rss;

import ani.rss.download.qBittorrent;
import ani.rss.entity.Config;
import ani.rss.util.basic.HttpReq;
import ani.rss.util.other.ConfigUtil;
import cn.hutool.extra.spring.SpringUtil;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.support.StaticApplicationContext;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * qBittorrent 授权方式测试
 * <p>
 * 使用内置 HttpServer 模拟 qBittorrent WebUI API, 验证 ApiKey 与账号密码两种授权方式
 */
@Slf4j
class qBittorrentAuthTest {

    static final String USERNAME = "admin";
    static final String PASSWORD = "admin123";
    static final String API_KEY = "qbt_mock-api-key";

    static HttpServer server;
    static int port;

    /**
     * 各路径最后一次请求携带的认证头
     */
    static final Map<String, String> LAST_COOKIE = new ConcurrentHashMap<>();
    static final Map<String, String> LAST_AUTH = new ConcurrentHashMap<>();

    /**
     * 服务端当前有效会话ID, 每次登录成功后刷新
     */
    static volatile String currentSid;

    /**
     * 是否校验会话, 用于模拟会话过期
     */
    static volatile boolean sidCheckEnabled = true;

    static volatile int loginCount = 0;

    @BeforeAll
    static void start() throws IOException {
        // 非Spring环境下提供 BuildProperties, 供 MavenUtils 获取版本号
        StaticApplicationContext context = new StaticApplicationContext();
        Properties properties = new Properties();
        properties.setProperty("version", "3.2.20");
        context.getBeanFactory()
                .registerSingleton("buildProperties", new BuildProperties(properties));
        context.refresh();
        new SpringUtil().setApplicationContext(context);

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();

        server.createContext("/api/v2/auth/login", exchange -> {
            loginCount++;
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            boolean ok = body.contains("username=" + USERNAME)
                    && body.contains("password=" + PASSWORD);
            if (!ok) {
                send(exchange, 200, "Fails.");
                return;
            }
            // 登录成功, 下发新的会话
            currentSid = "sid-" + System.nanoTime();
            sidCheckEnabled = true;
            exchange.getResponseHeaders()
                    .add("Set-Cookie", "SID=" + currentSid + "; path=/");
            send(exchange, 200, "Ok.");
        });

        server.createContext("/api/v2/app/version", exchange -> {
            if (!authorized(exchange)) {
                send(exchange, 403, "Forbidden");
                return;
            }
            send(exchange, 200, "v5.1.2");
        });

        server.createContext("/api/v2/torrents/info", exchange -> {
            if (!authorized(exchange)) {
                send(exchange, 403, "Forbidden");
                return;
            }
            send(exchange, 200, "[]");
        });

        server.start();
    }

    @BeforeEach
    void resetState() {
        // 清空全局Cookie管理器, 保证测试之间互不影响
        HttpReq.COOKIE_MANAGER.getCookieStore().removeAll();
        LAST_COOKIE.clear();
        LAST_AUTH.clear();
        currentSid = null;
        sidCheckEnabled = true;
        loginCount = 0;
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    static boolean authorized(HttpExchange exchange) {
        String path = exchange.getRequestURI().getPath();
        // ConcurrentHashMap 不允许null值, 缺失的头部以空串记录
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        String auth = exchange.getRequestHeaders().getFirst("Authorization");
        LAST_COOKIE.put(path, cookie == null ? "" : cookie);
        LAST_AUTH.put(path, auth == null ? "" : auth);

        if (null != auth && auth.equals("Bearer " + API_KEY)) {
            return true;
        }

        return sidCheckEnabled && null != currentSid
                && null != cookie && cookie.contains("SID=" + currentSid);
    }

    static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    static Config config() {
        Config config = ConfigUtil.CONFIG;
        config.setDownloadToolType("qBittorrent");
        config.setDownloadToolHost("http://127.0.0.1:" + port);
        config.setProxy(false);
        config.setProxyList("");
        return config;
    }

    @Test
    void accountPasswordLoginAndRequest() {
        Config config = config();
        config.setDownloadToolUsername(USERNAME);
        config.setDownloadToolPassword(PASSWORD);

        qBittorrent qb = new qBittorrent(null);

        assertTrue(qb.login(true, config), "账号密码登录失败");

        Boolean ok = qBittorrent.getApi("/api/v2/torrents/info")
                .thenFunction(res -> res.isOk());
        assertTrue(ok, "登录后请求失败");

        String cookie = LAST_COOKIE.get("/api/v2/torrents/info");
        assertTrue(cookie != null && cookie.contains("SID=" + currentSid),
                "请求应携带登录后的会话: " + cookie);
    }

    @Test
    void accountPasswordLoginWrongCredentials() {
        Config config = config();
        config.setDownloadToolUsername(USERNAME);
        config.setDownloadToolPassword("wrong-password");

        qBittorrent qb = new qBittorrent(null);

        assertFalse(qb.login(true, config), "错误密码不应登录成功");

        // 登录失败后请求应被拒绝
        Boolean ok = qBittorrent.getApi("/api/v2/torrents/info")
                .thenFunction(res -> res.isOk());
        assertFalse(ok, "未登录时请求应被拒绝");
    }

    @Test
    void accountPasswordMissingUsername() {
        Config config = config();
        config.setDownloadToolUsername("");
        config.setDownloadToolPassword(PASSWORD);

        qBittorrent qb = new qBittorrent(null);

        assertFalse(qb.login(true, config), "缺少用户名时不应登录成功");
    }

    @Test
    void apiKeyLoginAndRequest() {
        Config config = config();
        config.setDownloadToolUsername("");
        config.setDownloadToolPassword(API_KEY);

        qBittorrent qb = new qBittorrent(null);

        assertTrue(qb.login(true, config), "ApiKey 登录失败");

        Boolean ok = qBittorrent.getApi("/api/v2/torrents/info")
                .thenFunction(res -> res.isOk());
        assertTrue(ok, "ApiKey 模式下请求失败");

        assertEquals("Bearer " + API_KEY, LAST_AUTH.get("/api/v2/torrents/info"),
                "应携带 ApiKey 授权头");
    }

    @Test
    void apiKeyWrongKey() {
        Config config = config();
        config.setDownloadToolUsername("");
        config.setDownloadToolPassword("qbt_wrong-key");

        qBittorrent qb = new qBittorrent(null);

        assertFalse(qb.login(true, config), "错误 ApiKey 不应登录成功");
    }

    @Test
    void sessionReuseSkipsRelogin() {
        Config config = config();
        config.setDownloadToolUsername(USERNAME);
        config.setDownloadToolPassword(PASSWORD);

        qBittorrent qb = new qBittorrent(null);

        assertTrue(qb.login(true, config));

        // 会话有效时不再重复登录
        int loginsBefore = loginCount;
        assertTrue(qb.login(false, config));
        assertEquals(loginsBefore, loginCount, "会话有效时不应重新登录");

        // test=true 时强制重新登录
        assertTrue(qb.login(true, config));
        assertEquals(loginsBefore + 1, loginCount, "test=true 应重新登录");
    }

    @Test
    void expiredSessionTriggersRelogin() {
        Config config = config();
        config.setDownloadToolUsername(USERNAME);
        config.setDownloadToolPassword(PASSWORD);

        qBittorrent qb = new qBittorrent(null);

        assertTrue(qb.login(true, config));
        int loginsBefore = loginCount;

        // 模拟服务端会话过期
        sidCheckEnabled = false;
        Boolean forbidden = qBittorrent.getApi("/api/v2/torrents/info")
                .thenFunction(res -> res.isOk());
        assertFalse(forbidden);

        // 会话失效后应重新登录并恢复
        assertTrue(qb.login(false, config));
        assertEquals(loginsBefore + 1, loginCount, "会话失效时应重新登录");

        Boolean ok = qBittorrent.getApi("/api/v2/torrents/info")
                .thenFunction(res -> res.isOk());
        assertTrue(ok, "重新登录后请求应恢复正常");
    }

    /**
     * 独立运行入口
     * <p>
     * 部分安全软件会干扰 maven surefire 派生进程的回环连接, 导致集成测试无法在 surefire 中运行,
     * 可通过以下命令独立执行全部用例:
     * <pre>
     * java -cp "target/test-classes;target/classes;依赖classpath" ani.rss.qBittorrentAuthTest
     * </pre>
     *
     * @param args 无参数
     */
    public static void main(String[] args) throws Exception {
        start();
        int failures = 0;
        qBittorrentAuthTest instance = new qBittorrentAuthTest();
        java.util.function.Function<Runnable, Boolean> run = check -> {
            try {
                instance.resetState();
                check.run();
                return true;
            } catch (Throwable e) {
                log.error("FAIL => {}", e.getMessage());
                return false;
            }
        };

        failures += run.apply(instance::accountPasswordLoginAndRequest) ? 0 : 1;
        log.info("accountPasswordLoginAndRequest 完成");
        failures += run.apply(instance::accountPasswordLoginWrongCredentials) ? 0 : 1;
        log.info("accountPasswordLoginWrongCredentials 完成");
        failures += run.apply(instance::accountPasswordMissingUsername) ? 0 : 1;
        log.info("accountPasswordMissingUsername 完成");
        failures += run.apply(instance::apiKeyLoginAndRequest) ? 0 : 1;
        log.info("apiKeyLoginAndRequest 完成");
        failures += run.apply(instance::apiKeyWrongKey) ? 0 : 1;
        log.info("apiKeyWrongKey 完成");
        failures += run.apply(instance::sessionReuseSkipsRelogin) ? 0 : 1;
        log.info("sessionReuseSkipsRelogin 完成");
        failures += run.apply(instance::expiredSessionTriggersRelogin) ? 0 : 1;
        log.info("expiredSessionTriggersRelogin 完成");

        stop();
        log.info("测试结束, 失败数: {}", failures);
        if (failures > 0) {
            System.exit(1);
        }
    }
}
