🌐 CF-Worker 优选订阅生成器 (Optimized Sub Generator)

这是一个基于 Cloudflare Workers 构建的轻量级、高性能“优选节点订阅生成器”。它能够将你的基础节点链接（VLESS / VMess / Trojan）与海量优选 IP（本地私有库或外部公开 API）进行裂变组合，生成包含多条高质量优选线路的专属订阅链接。

自带可视化的优选 IP 管理后台与自定义短链系统，完美解决订阅链接过长、节点信息暴露等痛点。

<img width="1912" height="902" alt="image_2026-06-11_10-38-25" src="https://github.com/user-attachments/assets/ac982991-e1e8-403e-883b-da8419cc55ef" />

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

✨ 核心特性
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
⚡ 节点多路复用 (Multiplexing)：输入单条基础节点，自动替换伪装 Host 和 SNI，瞬间裂变出成百上千条优选节点。

🔗 原生短链支持：内置基于 Cloudflare KV 的短链系统，订阅链接短小精悍，支持 302 自动重定向，完美兼容主流代理客户端（V2rayN、Clash 等）。

🛡️ 安全与防滥用：

Token 验证：订阅接口受专属 SUB_TOKEN 保护，防止接口被他人盗刷。

Basic Auth：后台管理面板受严格的账号密码保护。

伪装报错节点：当参数错误或外部拉取失败时，会自动下发一条“带有报错信息的伪装 VLESS 节点”，直接在客户端列表显示错误原因，排错极其方便。

📊 双模式数据源：

私有本地库：搭配可视化 Admin 面板，支持批量导入、查重、按国家地区排序以及单节点启停。

外部接口拉取：支持实时拉取第三方动态测速 API（如电信/联通/移动优先库），并自带反防 CC 拦截的兜底逻辑。

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
🛠️ 部署指南

本项目完全依赖 Cloudflare 的 Serverless 生态，你需要准备：一个 Cloudflare 账号，以及用于绑定的 KV 空间和 D1 数据库。

第一步：创建依赖资源

1.创建 KV 命名空间
前往 Cloudflare 控制台 -> Storage & Databases -> KV

创建一个新的命名空间，建议命名为 sub_task_kv

创建 D1 数据库并建表

前往 Storage & Databases -> D1

创建一个新的数据库，建议命名为 sub_ips_db

进入该数据库的 Console (控制台)，执行以下 SQL 语句初始化表结构：

CREATE TABLE ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    name TEXT,
    active INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 0
);

第二步：部署 Worker

前往 Workers & Pages，点击 Create Application -> Create Worker。

命名你的 Worker（例如 my-sub-gen）并点击部署。

点击 Edit code，将本项目的 worker.js 代码完整粘贴进去，点击 Deploy。

第三步：绑定环境变量与资源

在 Worker 的 设置 -> Variables & Secrets 中进行如下配置：

1. 绑定 KV 命名空间 (KV Namespace Bindings)

Variable name: TASK_KV (必须完全一致)

KV namespace: 选择你刚才创建的 sub_task_kv

2. 绑定 D1 数据库 (D1 Database Bindings)

Variable name: DB (必须完全一致)

D1 database: 选择你刚才创建的 sub_ips_db

3. 设置环境变量 (Environment Variables)

ADMIN_PASSWORD：设置后台管理面板的登录密码（例如 Admin@123）。登录账号任意，密码需与此一致。

SUB_TOKEN：设置生成订阅的安全秘钥（例如 MySecretToken888），用户前端生成时必须填写。
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
🚀 使用说明

1. 公开订阅生成页 (/)

访问你的 Worker 域名主页（如 https://your-worker.workers.dev/）：

填入你的基础节点（支持 vless://， vmess://， trojan://）。

选择 IP 来源（本地后台配置 或 外部接口）。

填入你设置的 SUB_TOKEN。

点击生成，即可获得形如 https://your-worker.workers.dev/s/xyz123 的专属短链订阅及二维码。

2. 后台管理面板 (/admin)

访问 https://your-worker.workers.dev/admin：

触发浏览器 Basic Auth 验证。用户名字段可留空或随意填写，密码填写你设置的 ADMIN_PASSWORD。

进入面板后，你可以：

批量粘贴并导入优选 IP（格式支持 IP:端口#地区备注）。

一键清理重复 IP、按地区自动排序。

单独启用/禁用某个表现不佳的优选 IP。

📝 隐私占位符修改提醒

在克隆或 fork 本项目代码部署前，请全局搜索并替换 worker.js 中的以下占位符为你自己的个性化信息：

YOUR_BRAND_NAME：你的品牌或网站名称。

YOUR_BACKGROUND_IMAGE_URL：首页背景图 URL。

YOUR_AVATAR_IMAGE_URL：首页头像/Logo URL。

YOUR_TELEGRAM：获取 Token 的个人 Telegram 链接。

YOUR_GROUP：你的交流群组链接。

YOUR_NAME：页脚的维护者署名。

example.com：如果你有自己的外部测速 API，请将下拉列表中的示例域名替换掉。

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
⚠️ 免责声明
本项目仅供网络技术学习、研究与交流使用。请勿用于任何违反当地法律法规的非法用途。开发者不对使用本程序所造成的任何后果负责。

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## ⭐  ⭐  ⭐ Star 星星走起
## Star History 
<a href="https://www.star-history.com/?repos=xiagefei%2FGeFei-Sub-Worker-&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=xiagefei/GeFei-Sub-Worker-&type=date&theme=dark&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=xiagefei/GeFei-Sub-Worker-&type=date&legend=bottom-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=xiagefei/GeFei-Sub-Worker-&type=date&legend=bottom-right" />
 </picture>
</a>

# 🙏 致谢 
[DesireOr2](https://github.com/DesireOr2/Desire-Sub-Worker)引用二次修改
