# 进程拦截工具（Block Ads）

> 本项目用于在 Windows 上基于**目录**与**签名**规则，对特定程序的运行进行拦截或放行，并提供可视化管理界面（WebView2）。

## 下载地址
> [蓝奏云](https://bluered.lanzouo.com/iUDUv3bu73rc)
> [Release](https://github.com/AzureIvory/block-ads/releases/tag/Release)

## 文件说明

| 文件 | 作用 |
|---|---|
| **`folder.txt`** | 目录黑名单：匹配目录下的程序将被拦截 |
| **`sign.txt`** | 签名黑名单：匹配数字签名信息的程序将被拦截 |
| **`Wfolder.txt`** | 目录白名单：匹配目录下的程序将被放行 |
| **`Wsign.txt`** | 签名白名单：匹配数字签名信息的程序将被放行 |
| **`note.txt`** | 注释：用于给条目添加说明 |
| **`UI.exe`** | 图形化界面：用于管理名单、查看拦截记录、启动/停止核心功能 |
| **`Code.exe`** | 伪装程序：用于伪装特定人群 |
| **`block-ads.exe`** | 核心拦截程序 |
---

## 效果展示

![效果](tools/eg.gif)

## 卸载示例

![卸载](tools/uninst.gif)

---


## 使用说明
### 运行环境
- Windows 7以上
- 需要安装 **WebView2 Runtime**

### 快速开始
1. 安装 WebView2 Runtime。
2. 解压发布包后，运行 `UI.exe`。
3. 在 UI 中配置黑名单/白名单。
4. 点击“启动”启用拦截；需要临时放行时可点击“停止”，再将目标程序目录/签名加入白名单后重新启动。

### 通过拦截记录定位软件
- 在拦截记录列表中双击条目，可定位对应程序/路径

## 一键伪装

>#### 1.伪装虚拟机
>- 将会设置HKEY_CLASSES_ROOT\Applications\VMwareHostOpen.exe\shell\open\command的默认值
>#### 2.伪装vip
>- 设置%APPDATA%\TabXExplorer\config.ini 文件中 settings 节的 level 值
>#### 3.伪装360弹窗过滤模式
>- 设置HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\360Safe\stat项中 noadpop 与 advtool_PopWndTracker 的键值
>#### 4.伪装禁止投放广告人群
>- 将会调用默认浏览器访问一次知乎"zhihu.com"
>#### 5.伪装安装火绒
>- 将会在HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall新增一个火绒的安装项和"DisplayIcon"键
>#### 6.伪装技术人员
>- 将会在后台运行一个空壳程序"Code.exe"(vscode),其中窗口类名为"CabinetWClass",标题为"控制面板"


## 浏览器侧的广告治理建议
>#### 第一步浏览器下载安装油猴
>[油猴官网](https://www.tampermonkey.net/index.php)

>[油猴crx下载（适用于谷歌等特殊浏览器）](https://bluered.lanzouo.com/i1jfd3b90kfe)

>[本地crx插件安装教程](https://blog.csdn.net/chouchoubuchou/article/details/146294436)

>#### 第二步安装这个脚本
>[AC-baidu-重定向优化百度搜狗谷歌必应搜索](https://openuserjs.org/scripts/inDarkness/AC-baidu-%E9%87%8D%E5%AE%9A%E5%90%91%E4%BC%98%E5%8C%96%E7%99%BE%E5%BA%A6%E6%90%9C%E7%8B%97%E8%B0%B7%E6%AD%8C%E5%BF%85%E5%BA%94%E6%90%9C%E7%B4%A2_favicon_%E5%8F%8C%E5%88%97)


# 运行时
>[webview2](https://developer.microsoft.com/zh-cn/microsoft-edge/webview2)

# 库
- github.com/bi-zone/etw  
- golang.org/x/sys/windows  
- github.com/webview/webview_go  
- golang.org/x/sys/windows/registry  


## 编译
> go build -ldflags="-H=windowsgui -s -w" -trimpath

# 致谢
[SoftCnKiller](https://github.com/SiHaiYiYeQiu/SoftCnKiller)
