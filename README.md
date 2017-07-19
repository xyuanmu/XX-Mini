# XX-Mini

下载地址：[![GitHub release](https://img.shields.io/github/release/xyuanmu/XX-Mini.svg)](https://git.io/XX-Mini)

## 软件说明
* 源码取自 [XX-Net](https://github.com/XX-net/XX-Net) 项目，精简 web UI、php_proxy 以及 x_tunnel 等功能，只保留 gae_proxy 以及自动扫描IP功能。
* 用户数据保存到 data 目录，运行软件后会自动生成，支持 manual.ini 配置文件，自定义IP段 ip_range.txt。
* 代码为 Linux 版本，欢迎提交 commit，提交代码后一段时间内会同步到 Windows 版本提供下载。
* idea 来自 [XX-Net#2301](https://github.com/XX-net/XX-Net/issues/2301)，模块简单，未部署谷歌appid者请慎重使用！如果熟悉 GoAgent 和 XX-Net 会很快上手。

## 使用说明
### Windows：
* 下载 Windows 版本解压后，第一次以管理员身份运行 goagent.exe 等待一段时间扫描IP（半小时左右）
* 当有足够IP的时候右键点击系统托盘 goagent 图标 - 设置 IE 代理，选择 `http://127.0.0.1:8086/proxy.pac`
* 接下来即可使用IE进行翻墙，但公共appid不允许观看视频和下载
* 双击 addto-startup.js 脚本可以添加开机启动项

### Linux：
* 下载 Linux 版本解压后，打开终端，定位到 XX-Mini 目录，输入 `python proxy.py` 等待一段时间扫描IP
* 之后设置浏览器代理为：127.0.0.1，端口：8087，支持pac自动代理的设置为 `http://127.0.0.1:8086/proxy.pac`
* 接下来即可使用浏览器翻墙，但公共appid不允许观看视频和下载
* 在 XX-Mini 目录，输入 `python addto-startup.py` 可以添加系统启动项
* 在 XX-Mini 目录，输入 `python goagent-gtk.py` 可以显示系统托盘

### egg 文件打包方法：
* 将lib**文件夹下**的文件打包成 lib.zip 压缩包，记住不是打包lib文件夹！
* 修改压缩包后缀 zip 为 egg 即可

### proxy.ini 配置文件说明：
建议大家在 data 目录新建一份 manual.ini 文件，优先级大于 proxy.ini 设置，避免升级的时候设置丢失。
```ini
[listen]
;监听地址，如果需要允许局域网/公网使用，设为0.0.0.0即可，若共享pac此项必须设置为 0.0.0.0
ip = 127.0.0.1
;默认使用8087作为代理端口，如有需要可以修改
port = 8087
;局域网代理认证用户名，留空不开启认证
username =
;代理认证密码
password =
;启动后是否隐藏 goagent 窗口，0为隐藏（最小化至托盘），1为显示
visible = 0
;是否显示详细debug信息
debuginfo = 0

[gae]
;添加你自己的appid，多个用竖线 | 分隔
appid = 
;appid密码，无可不填
password = 

;类似于系统 hosts 功能，指定各网站连接方式为 direct(直接通过IP连接) 或 gae(通过gae连接)
[hosts]
;表示直接通过IP连接 www.google.com，但非 www 开头的不使用直连
www.google.com = direct
;前面加 . 表示只要匹配域名即使用 gae 模式
.commondatastorage.googleapis.com = gae


;下载分流，建议使用默认值
[autorange]
;线程数，当观看视频不流畅可适当增加
threads = 20
;分块大小，如果IP质量好可以修改 maxsize 为更大的数值
maxsize = 548576

;pac 自动配置脚本
[pac]
;是否启用
enable = 1
;监听地址，如果需要允许局域网/公网使用，设为0.0.0.0，同时设置 [listen] ip = 0.0.0.0 否则无效
ip = 127.0.0.1
;默认使用8086作为代理端口，如有需要可以修改
port = 8086
;pac 文件名
file = proxy.pac
;是否开启广告拦截模式
admode = 1
;广告拦截规则订阅地址
adblock = https://easylist-downloads.adblockplus.org/easylistchina.txt
;被墙网站规则订阅地址
gfwlist = https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
;更新时间，以秒计算
expired = 86400

;前置代理
[proxy]
;是否启用，改为1启用
enable = 0
;代理类型，支持 HTTP HTTPS SOCK4 SOCK5
type = HTTP
host = 127.0.0.1
port = 8888
user =
passwd =

[google_ip]
;开启 IPv6 选项，1开启，0关闭，慎重！
use_ipv6 = 0
;自动调整扫描线程数
auto_adjust_scan_ip_thread_num = 1
;扫描线程数，默认50，若出现网络连接缓慢可改小一点
max_scan_ip_thread_num = 50
;谷歌IP上限，超过则剔除延时高的IP
max_good_ip_num = 3000
;IP连接时间间隔，出现连接不稳定可适当调整
ip_connect_interval = 8
;单个IP连接数，建议别改，容易使IP失效
max_links_per_ip = 1

;连接设置，一般无需修改
[connect_manager]
;最大连接线程
https_max_connect_thread = 10
;每次添加的新连接池数
https_new_connect_num = 3
;最小连接池数值
https_connection_pool_min = 1
;最大连接池数值
https_connection_pool_max = 30

[system]
;设置成 1 会在data目录生成日志文件 local.log，便调试用
log_file = 0
;设置是否在data目录输出扫描IP日志 scan_ip.log，超过3000行会新建日志
log_scan = 1
```
