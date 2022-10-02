<div align="center">
 <h1>
    大和セキュリティによる、SigmaユーザのためのWindowsイベントログ設定と監視ガイド
 </h1>
 [<a href="README.md">English</a>] | [<b>日本語</b>]
</div>
<p>

**注意: 現在、日本語版はできていません。和訳の手伝いしたい方を募集しています！**

これは、Windowsのイベントログの設定と監視に関するガイドで、Sigmaルールが何かを検出するために、適切なログを有効にすることに重点を置いています。

# TLDR

* Windowsのデフォルトの監査設定では[sigma](https://github.com/SigmaHQ/sigma)ルールの10~20%程度しか利用できません。
* Windowsのログが有効になっていても、デフォルトではログの最大サイズがたった1〜20MBなので、すぐに証拠が上書きされてしまう可能性が高いです。
* Sigmaルールの約75%まで利用可能にし、必要なだけログを保持するように[YamatoSecurityConfigureWinEventLogs.bat](YamatoSecurityConfigureWinEventLogs.bat)の導入で適切な監査設定を行いましょう。
    - **注意: 必要に応じてスクリプトをカスタマイズし、本番環境で導入する前に必ずテストしてください！**
* 100%のSigmaルールを利用したい方は、[sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)を導入する必要があります。（お勧め！）

## 目次

- [TLDR](#tldr)
  - [目次](#目次)
- [作者](#作者)
- [Acknowledgements](#acknowledgements)
- [デフォルトの Windows ログ設定の問題](#デフォルトの-windows-ログ設定の問題)
- [注意: 自己責任で使用してください](#注意-自己責任で使用してください)
- [重要な Windowsイベントログ](#重要な-windowsイベントログ)
  - [Sigmaのトップログソース](#sigmaのトップログソース)
    - [上位のSigmaログソース](#上位のsigmaログソース)
    - [上位のSecurityイベンドID](#上位のsecurityイベンドid)
- [最大ファイル サイズの増加](#最大ファイル-サイズの増加)
  - [オプション 1: イベント ビューア(手動)](#オプション-1-イベント-ビューア手動)
  - [オプション 2: Windowsビルトインツール](#オプション-2-windowsビルトインツール)
  - [オプション 3: PowerShell](#オプション-3-powershell)
  - [オプション 4: グループポリシー](#オプション-4-グループポリシー)
- [ログ設定を改善するスクリプト](#ログ設定を改善するスクリプト)
- [ログ設定の改善](#ログ設定の改善)
  - [Sysmonログ (Sigmaルール1382件)](#sysmonログ-sigmaルール1382件)
  - [Securityログ (Sigmaルール 1045件(process creationルール903件 + その他ルール142件))](#securityログ-sigmaルール-1045件process-creationルール903件--その他ルール142件)
  - [Powershellログ (Sigmaルール 175件)](#powershellログ-sigmaルール-175件)
    - [モジュールログ (Sigmaルール 30件)](#モジュールログ-sigmaルール-30件)
      - [モジュールログの有効化](#モジュールログの有効化)
        - [オプション 1: グループポリシーによる有効化](#オプション-1-グループポリシーによる有効化)
        - [オプション 2: レジストリによる有効化](#オプション-2-レジストリによる有効化)
    - [スクリプトブロックログ (Sigmaルール 134件)](#スクリプトブロックログ-sigmaルール-134件)
      - [スクリプトブロックログの有効化](#スクリプトブロックログの有効化)
      - [オプション 1: グループポリシーによる有効化](#オプション-1-グループポリシーによる有効化-1)
      - [オプション 2: レジストリによる有効化](#オプション-2-レジストリによる有効化-1)
    - [Transcription logging](#transcription-logging)
      - [Enabling Transcription logging](#enabling-transcription-logging)
        - [オプション 1: グループポリシーによる有効化](#オプション-1-グループポリシーによる有効化-2)
        - [オプション 2: レジストリによる有効化](#オプション-2-レジストリによる有効化-2)
    - [参考記事](#参考記事)
  - [Systemログ (Sigmaルール 55件)](#systemログ-sigmaルール-55件)
  - [Applicationログ (Sigmaルール 16件)](#applicationログ-sigmaルール-16件)
  - [Windows Defender Operationalログ (Sigmaルール 10件)](#windows-defender-operationalログ-sigmaルール-10件)
  - [Bits-Client Operationalログ (Sigmaルール 6件)](#bits-client-operationalログ-sigmaルール-6件)
  - [Firewallログ (Sigmaルール 6件)](#firewallログ-sigmaルール-6件)
  - [NTLM Operationalログ (Sigmaルール 3件)](#ntlm-operationalログ-sigmaルール-3件)
  - [Security-Mitigations KernelModeとUserModeログ (Sigmaルール 2件)](#security-mitigations-kernelmodeとusermodeログ-sigmaルール-2件)
  - [PrintServiceログ (Sigmaルール 2件)](#printserviceログ-sigmaルール-2件)
    - [Adminログ (Sigmaルール 1件)](#adminログ-sigmaルール-1件)
    - [Operationalログ (Sigmaルール 1件)](#operationalログ-sigmaルール-1件)
  - [SMBClient Securityログ (Sigmaルール 2件)](#smbclient-securityログ-sigmaルール-2件)
  - [AppLockerログ (Sigmaルール 1件)](#applockerログ-sigmaルール-1件)
  - [CodeIntegrity Operationalログ (Sigmaルール 1件)](#codeintegrity-operationalログ-sigmaルール-1件)
  - [Diagnosis-Scripted Operationalログ (Sigmaルール 1件)](#diagnosis-scripted-operationalログ-sigmaルール-1件)
  - [DriverFrameworks-UserMode Operationalログ (Sigmaルール 1件)](#driverframeworks-usermode-operationalログ-sigmaルール-1件)
  - [WMI-Activity Operationalログ (Sigmaルール 1件)](#wmi-activity-operationalログ-sigmaルール-1件)
  - [TerminalServices-LocalSessionManager Operationalログ (Sigmaルール 1件)](#terminalservices-localsessionmanager-operationalログ-sigmaルール-1件)
  - [TaskScheduler Operationalログ (Sigmaルール 1件)](#taskscheduler-operationalログ-sigmaルール-1件)

# 作者
 
田中ザック ([@yamatosecurity](https://twitter.com/yamatosecurity))。より多くの研究とテストを行い、(検知ルールとドキュメンテーションの)改善の余地があるため、定期的に更新していく予定です。PRは歓迎され、喜んでコントリビューターとして追加させていただきます。

もし、このガイドが役に立つのであれば、GitHubで星を付けてください。更新し続けるモチベーションが上がります。

# Acknowledgements

多くの情報はマイクロソフトの[詳細なセキュリティ監査に関するFAQ](https://learn.microsoft.com/ja-jp/windows/security/threat-protection/auditing/advanced-security-auditing-faq), [sigma](https://github.com/SigmaHQ/sigma)ルール, [ACSCのガイド](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)、そして私自身の調査/テストから得たものです。特に[Sigmaコミュニティ](https://github.com/SigmaHQ/sigma/graphs/contributors)には、世の中のすべての防衛者のために脅威検知能力をオープンソースかつフリーにしてくれたことに感謝しています。

# デフォルトの Windows ログ設定の問題

既定では、Windows は悪意のあるアクティビティの検出と、フォレンジック調査の実行に必要な多くのイベントをログに記録しません。また、イベント ファイルのデフォルトの最大サイズは、従来のイベントログ(`Security`、`System`、`Application`)ではわずか20MB、PowrShellでは15MB、その他のほとんどすべてのログではわずか1MBであるため、証拠が上書きされる可能性が高くなります。システム管理者が Windows マシンを簡単に構成できるように、このリポジトリにはシンプルな PowerShell および バッチスクリプトが用意されており、インシデントが発生したときに必要なログを取得できます。大規模なネットワークの場合は、このドキュメントを参照として使用し、グループポリシーやInTuneを使用してエンドポイントを構成することをお勧めします。

# 注意: 自己責任で使用してください

あまりにも多くのログを有効にすることによる悪影響や、このリポジトリ内の何かの正確性について、一切の責任を負いません。
本番環境にロールアウトする前に、テストマシンでシステムに加えた変更を、理解しテストすることは、ユーザの責任です。
環境を模倣したテスト マシンで、少なくとも1週間はできるだけ多くのログ記録を有効にしてから、ノイズが多すぎるイベントがないか、必要なイベントが生成されているかどうかを確認することをお勧めします。

HayabusaのイベントID集計機能を使用して、evtxファイル内のイベントIDの総数と割合を表示できます。

例：`hayabusa.exe -M -f path/to/Security.evtx`

# 重要な Windowsイベントログ

* 有効にするべき最も重要なイベント ログは、おそらく`Process Creation`で、システムで実行されているプロセスを追跡するものです。
現在、Sigmaルールの約半分がこのイベントに関連しています。
これは、Sysmonをインストールして、イベントID 1を有効にするか、ビルトインログ (SecurityイベントID 4688) を有効にすることで実現できます。  
Sysmon イベントID 1で、実行可能ファイルのハッシュやメタデータなどの詳細情報を取得するので理想的ですが、
Sysmon をインストールできない場合は、Windows のbuilt-in機能で有効にすることができます。
ただし、多くの検出ルールがこれに依存しているため、コマンド ライン ログも有効にすることが重要です。
残念ながらSecurity イベントID4688は、Sysmonプロセス作成ログほど詳細な情報は提供されません。
* 2 番目に重要なイベント ログは、適切に調整されたセキュリティログです。
* 3 番目に重要なのはおそらく(攻撃者は PowerShell を悪用することが多いため)、PowerShell モジュールのログ記録と ScriptBlock のログ記録です。
* 4 番目は、おそらく他のすべてのSysmonイベントです。
* これらの他に、「アプリケーションとサービス ログ」フォルダーの下には、非常に重要な他の多くのログがあります。
セキュリティ緩和、Windows Defender、セキュリティが強化された Windows ファイアウォール、WMI アクティビティなど。

## Sigmaのトップログソース

![WindowsEventsWithSigmaRules](WindowsEventsWithSigmaRules.png)

デフォルトのWindows監査設定で使用できるSigmaルールは、約10〜20%です。

### 上位のSigmaログソース

![SigmaTopLogSources](SigmaTopLogSources.png)

### 上位のSecurityイベンドID

![TopSecurityEventIDs](TopSecurityEventIDs.png)

# 最大ファイル サイズの増加

## オプション 1: イベント ビューア(手動)

これを大規模に行うのは現実的ではありませんが、ログの有効、無効を変更し、最大ファイル サイズを確認および構成する最も簡単な方法は、イベント ビューアでログを右クリックして`プロパティ`を開くことです。

## オプション 2: Windowsビルトインツール

標準搭載のwevtutilコマンドを使用できます。

例: `wevtutil sl Security /ms:1073741824` (セキュリティログの最大ファイルサイズを1GBに増やす)

## オプション 3: PowerShell

## オプション 4: グループポリシー

`Security`、`System`、`Application`などの従来のイベント ログの最大ファイル サイズを増やすのは簡単ですが、
残念ながら、他のイベント ログの最大ファイル サイズを変更するには、管理者テンプレートをインストールするか、レジストリを直接変更する必要があります。
起動時に`.bat`スクリプトを使用してファイル サイズを増やす方が簡単な場合があります。

# ログ設定を改善するスクリプト

最大ファイル サイズを増やして適切なログを有効にするスクリプトが、[YamatoSecurityConfigureWinEventLogs.bat](YamatoSecurityConfigureWinEventLogs.bat)で提供されています。

# ログ設定の改善

## Sysmonログ (Sigmaルール1382件)

ファイル: `Microsoft-Windows-Sysmon%4Operational.evtx`

デフォルトの設定: `インストールされていない`

sysmonをインストールして設定することは、Windows エンドポイントでの可視性を高めるための最善の方法ですが、計画、テスト、およびメンテナンスが必要になります。

これはそれ自体が大きなトピックであるため、現時点ではこのドキュメントの範囲外です。次のリソースを確認してください。
TrustedSecのSysmonコミュニティガイド: [https://github.com/trustedsec/SysmonCommunityGuide](https://github.com/trustedsec/SysmonCommunityGuide)
Sysmon Modular: [https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
Florian Roth氏によるSwift On SecurityのSysmon設定ファイルを更新しているフォーク: [https://github.com/Neo23x0/sysmon-config](https://github.com/Neo23x0/sysmon-config)
Ion-storm氏によるSwift On SecurityのSysmon設定ファイルを更新しているフォーク: [https://github.com/ion-storm/sysmon-config](https://github.com/ion-storm/sysmon-config)


## Securityログ (Sigmaルール 1045件(process creationルール903件 + その他ルール142件))

ファイル: `Security.evtx`

デフォルトの設定: `一部有効`

Securityログの設定が最も複雑なため、別のドキュメントを作成しました: [ConfiguringSecurityLogAuditPolicies-Japanese.md](ConfiguringSecurityLogAuditPolicies-Japanese.md)

## Powershellログ (Sigmaルール 175件)

ファイル: `Microsoft-Windows-PowerShell%4Operational.evtx`

### モジュールログ (Sigmaルール 30件)

モジュールログを有効にすると、イベントID`4103`が記録されます。
モジュールログには、古いOSやバージョンのPowerShellでも動作する利点がある: PowerShell 3.0 (Win 7+)。
また、実行したPowerShellコマンドとその結果の両方をログに残すことができるのも利点です。
デメリットは、イベント数が極端に多くなってしまうことです。
例えば、攻撃者がMimikatzを実行した場合、2000以上のイベントを含む7MBのログが作成されます！

#### モジュールログの有効化

デフォルトの設定: `監査なし`

##### オプション 1: グループポリシーによる有効化

グループポリシーエディター(`gpedit.msc`)で、`コンピューターの構成 > 管理用テンプレート > Windowsコンポーネント > Windows PowerShell`を開き、`モジュールログを有効にする`を有効にします。
`オプション`ペインで、`表示...`ボタンをクリックすると、ログを記録するモジュールを設定できます。
すべてのモジュールを記録するには、`値`テキストボックスに`*`を入力します。

##### オプション 2: レジストリによる有効化
```
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging → EnableModuleLogging = 1
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging \ModuleNames → * = *
```

### スクリプトブロックログ (Sigmaルール 134件)

デフォルトの設定: `On Win 10+, if a PowerShell script is flagged as suspicious by AMSI, it will be logged with a level of Warning.`

Turning on Script Block logging will enable event ID `4104` as well as `4105` and `4106` if you enable `Log script block invocation start / stop events`, however, it is not recommended to enable the script block invocation start and stop events. 
It is supported by default in PowerShell 5.0+ (Win 10+), however you can enable this on older OSes (Win 7+) if you install .NET 4.5 and WMF 4.0+.
Unfortunately, the maximum size of a single Windows event log is 32 KB so any PowerShell scripts greater than this will be fragmented in 32 KB sized blocks.
If you have the original PowerShell Operational `.evtx` file, you can use the [block-parser](https://github.com/matthewdunwoody/block-parser) tool to un-fragment these logs into a single easily readable text file.
One good thing about Script Block logging is that even if a malicious script is obfuscated with XOR, Base 64, ROT13, etc... the decoded script will be logged making analysis much easier.
The logs are more reasonable to work with than module logging as if an attacker runs Mimikatz, only 5 MB and 100 events will generated compared to the 7 MB and over 2000 events.
However, the output of the commands are not recorded with Script Block logging.

#### スクリプトブロックログの有効化

#### オプション 1: グループポリシーによる有効化

グループポリシーエディターで、`コンピューターの構成 > 管理用テンプレート > Windowsコンポーネント > Windows PowerShell`を開き、`PowerShellスクリプトブロックのログ記録を有効にする`を有効にします。

#### オプション 2: レジストリによる有効化

`HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1`

### Transcription logging

デフォルトの設定: `監査なし`

It is possible to also save PowerShell logs to text files on the local computer with transcription logs.
While an attacker can usually easily delete the transcription logs for anti-forensics, there may be scenarios where the attacker clears all of the event logs but does not search for transcription logs to delete. 
Therefore, it is recommended to also enable transcription logs if possible.
Ideally, transcript logs should be saved to a write-only network file share, however, this may be difficult to implement in practice.
Another benefit of transcription logs is they include the timestamp and metadata for each command and are very stroage efficient with less than 6 KB for Mimikatz execution. By default, they are saved to the user's documents folder. The downside is that the transcription logs only record what appears in the PowerShell terminal.

#### Enabling Transcription logging

##### オプション 1: グループポリシーによる有効化

グループポリシーエディターで、`コンピューターの構成 > 管理用テンプレート > Windowsコンポーネント > Windows PowerShell`を開き、`PowerShellトランスクリプションを有効にする`を有効にします。
その後、出力ディレクトリを指定します。

##### オプション 2: レジストリによる有効化

```
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription → EnableTranscripting = 1
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription → EnableInvocationHeader = 1
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription → OutputDirectory = “” (パスを入力する。空白の場合はデフォルトのパス。)
```

### 参考記事

* [Mandiant Blog: Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibilityt)

## Systemログ (Sigmaルール 55件)

ファイル: `System.evtx`

デフォルトの設定: `有効。20 MB`

Malware will often install services for persistence, local privilege esclation, etc... which can be found in this log.
It is also possible to detect various vulnerabilities being exploited here.

## Applicationログ (Sigmaルール 16件)

ファイル: `Application.evtx`

デフォルトの設定: `有効。20 MB`

This log is mostly noise but you may be able to find some important evidence here.
One thing to be careful about is that different vendors will use the same event IDs for different events so you should also filter on not just Event IDs but Provider Names as well.

## Windows Defender Operationalログ (Sigmaルール 10件)
 
ファイル: `Microsoft-Windows-Windows Defender%4Operational.evtx`

デフォルトの設定: `有効。1 MB`

You can detect not only Windows Defender alerts (which are important to monitor), but also exclusions being added, tamper protection being disabled, history deleted, etc...

## Bits-Client Operationalログ (Sigmaルール 6件)
 
ファイル: `Microsoft-Windows-Bits-Client%4Operational.evtx`

デフォルトの設定: `有効。1 MB`

Bitsadmin.exe is a popular [lolbin](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/) that attackers will abuse for downloading and executing malware.
You may find evidence of that in this log, although there will be a lot of false positives to watch out for.

## Firewallログ (Sigmaルール 6件)

ファイル: `Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx`

デフォルトの設定: `有効？ 1 MB`

You can find evidence of firewall rules being added/modified/deleted here.
Malware will often add firewall rules to make sure they can communicate with their C2 server, add proxy rules for lateral movement, etc...

## NTLM Operationalログ (Sigmaルール 3件)

ファイル: `Microsoft-Windows-NTLM%4Operational.evtx`

デフォルトの設定: `Enabled but Auditing is disabled. 1 MB`

This log is recommended to enable if you want to disable NTLM authentication. 
Disabling NTLM will most likely break some communication, so you can monitor this log on the DCs and other servers to see who is still using NTLM and disable NTLM gradually starting with those users before disabling it globally.
It is possible to detect NTLM being used for incoming connections in logon events such as 4624 but you need to enable this log if you want to monitor who is making outgoing NTLM connections.

To enable auditing, in Group Policy open `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options` and configure the proper various `Network security: Restrict NTLM:` settings.

Reference: [Farewell NTLM](https://www.scip.ch/en/?labs.20210909)

## Security-Mitigations KernelModeとUserModeログ (Sigmaルール 2件) 

Files: `Microsoft-Windows-Security-Mitigations%4KernelMode.evtx`, `Microsoft-Windows-Security-Mitigations%4UserMode.evtx`

デフォルトの設定: `有効。1 MB`

At the moment there are only 2 sigma rules for these logs but you should probably be collecting and monitoring all of the Exploit Protection, Network Protection, Controlled Folder Access and Attack Surface Reduction logs (About 40+ Event IDs). 

Unfortunately the Attack Surface Reduction logs (previously WDEG(Windows Defender Exploit Guard) and EMET) are spread across multiple logs and require complex XML queries to search them.

Details: [https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide)

## PrintServiceログ (Sigmaルール 2件)

It is recommended to enable the Operational log as well to detect Print Spooler attackers. (Ex: PrintNightmare, etc...)

### Adminログ (Sigmaルール 1件)

ファイル: `Microsoft-Windows-PrintService%4Admin.evtx`

デフォルトの設定: `有効。1 MB`

### Operationalログ (Sigmaルール 1件)

ファイル: `Microsoft-Windows-PrintService%4Operational.evtx`

デフォルトの設定: `Disabled. 1 MB`

## SMBClient Securityログ (Sigmaルール 2件) 

ファイル: `Microsoft-Windows-SmbClient%4Security.evtx`

デフォルトの設定: `有効。8 MB`

Used to attempt to detect PrintNightmare (Suspicious Rejected SMB Guest Logon From IP) and users mounting hidden shares.

## AppLockerログ (Sigmaルール 1件) 

Files: `Microsoft-Windows-AppLocker%4MSI and Script.evtx`, `Microsoft-Windows-AppLocker%4EXE and DLL.evtx`, `Microsoft-Windows-AppLocker%4Packaged app-Deployment.evtx`, `Microsoft-Windows-AppLocker%4Packaged app-Execution.evtx`

デフォルトの設定: `Enabled if AppLocker is enabled? 1 MB`

This is important to make sure is enabled and monitored if you are using AppLocker.

## CodeIntegrity Operationalログ (Sigmaルール 1件)

ファイル: `Microsoft-Windows-CodeIntegrity%4Operational.evtx`

デフォルトの設定: `有効。1 MB`

Check this log to detect driver load events that get blocked by Windows code integrity checks, which may indicate a malicious driver that faild to load.

## Diagnosis-Scripted Operationalログ (Sigmaルール 1件) 

Files: `Microsoft-Windows-Diagnosis-Scripted%4Operational.evtx`

デフォルトの設定: `有効。1 MB`

Evidence of diagcab packages being used for exploitation may be found here.

## DriverFrameworks-UserMode Operationalログ (Sigmaルール 1件) 

Files: `Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx`

デフォルトの設定: `監査なし。1 MB`

Detects plugged in USB devices.

## WMI-Activity Operationalログ (Sigmaルール 1件) 

ファイル: `Microsoft-Windows-WMI-Activity%4Operational.evtx`

デフォルトの設定: `Enabled on Win10+. 1 MB`

This is important to monitor as attackers will often exploit WMI for persistence and lateral movement.

## TerminalServices-LocalSessionManager Operationalログ (Sigmaルール 1件) 

ファイル: `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`

デフォルトの設定: `有効。1 MB`

Detects cases in which ngrok, a reverse proxy tool, forwards events to the local RDP port, which could be a sign of malicious behaviour

## TaskScheduler Operationalログ (Sigmaルール 1件) 

ファイル: `Microsoft-Windows-TaskScheduler%4Operational.evtx`

デフォルトの設定: `無効。1 MB`

Attackers will often abuse tasks for persistence and lateral movement so this should be enabled.