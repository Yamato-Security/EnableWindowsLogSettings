<div align="center">
 <h1>
    Securityログ設定について
 </h1>
 [<a href="ConfiguringSecurityLogAuditPolicies.md">English</a>] | [<b>日本語</b>]
</div>
<p>

現在、日本語版はありません。和訳したい方を募集しています！

# 目次

- [目次](#目次)
- [Notes about configuring Security log auditing](#notes-about-configuring-security-log-auditing)
- [Security Event Log Categories and Event IDs](#security-event-log-categories-and-event-ids)
  - [アカウント ログオン](#アカウント-ログオン)
    - [資格情報の確認の監査](#資格情報の確認の監査)
    - [Kerberos 認証サービスの監査](#kerberos-認証サービスの監査)
    - [Kerberos サービス チケット操作の監査](#kerberos-サービス-チケット操作の監査)
  - [アカウントの管理](#アカウントの管理)
    - [コンピューター アカウントの管理の監査](#コンピューター-アカウントの管理の監査)
    - [その他のアカウント管理イベントの監査](#その他のアカウント管理イベントの監査)
    - [セキュリティ グループの管理の監査](#セキュリティ-グループの管理の監査)
    - [ユーザー アカウントの管理の監査](#ユーザー-アカウントの管理の監査)
  - [詳細追跡](#詳細追跡)
    - [PNP アクティビティの監査](#pnp-アクティビティの監査)
    - [プロセス作成の監査](#プロセス作成の監査)
    - [プロセス終了の監査](#プロセス終了の監査)
    - [RPC (Remote Procedure Call) イベントの監査](#rpc-remote-procedure-call-イベントの監査)
    - [トークン権限の調整を監査する](#トークン権限の調整を監査する)
  - [DS (ディレクトリ サービス) アクセス](#ds-ディレクトリ-サービス-アクセス)
    - [ディレクトリ サービス アクセスの監査](#ディレクトリ-サービス-アクセスの監査)
    - [ディレクトリ サービスの変更の監査](#ディレクトリ-サービスの変更の監査)
  - [ログオン/ログオフ](#ログオンログオフ)
    - [アカウント ロックアウトの監査](#アカウント-ロックアウトの監査)
    - [グループ メンバーシップの監査](#グループ-メンバーシップの監査)
    - [ログオフの監査](#ログオフの監査)
    - [ログオンの監査](#ログオンの監査)
    - [その他のログオン/ログオフ イベントの監査](#その他のログオンログオフ-イベントの監査)
    - [特殊なログオンの監査](#特殊なログオンの監査)
  - [オブジェクト アクセス](#オブジェクト-アクセス)
    - [証明書サービスの監査](#証明書サービスの監査)
    - [詳細なファイル共有の監査](#詳細なファイル共有の監査)
    - [ファイル共有の監査](#ファイル共有の監査)
    - [ファイル システムの監査](#ファイル-システムの監査)
    - [フィルタリング プラットフォームの接続の監査](#フィルタリング-プラットフォームの接続の監査)
    - [フィルタリング プラットフォーム パケットの破棄の監査](#フィルタリング-プラットフォーム-パケットの破棄の監査)
    - [カーネルオブジェクトの監査](#カーネルオブジェクトの監査)
    - [その他のオブジェクト アクセス イベントの監査](#その他のオブジェクト-アクセス-イベントの監査)
    - [レジストリの監査](#レジストリの監査)
    - [リムーバブル記憶域の監査](#リムーバブル記憶域の監査)
    - [SAMの監査](#samの監査)
  - [ポリシーの変更](#ポリシーの変更)
    - [監査ポリシーの変更の監査](#監査ポリシーの変更の監査)
    - [認証ポリシーの変更の監査](#認証ポリシーの変更の監査)
    - [認可ポリシーの変更の監査](#認可ポリシーの変更の監査)
    - [フィルタリング プラットフォーム ポリシーの変更の監査](#フィルタリング-プラットフォーム-ポリシーの変更の監査)
    - [MPSSVC ルールレベル ポリシーの変更の監査](#mpssvc-ルールレベル-ポリシーの変更の監査)
    - [その他のポリシー変更イベントの監査](#その他のポリシー変更イベントの監査)
  - [特権の使用](#特権の使用)
    - [重要でない特権の使用の監査](#重要でない特権の使用の監査)
    - [重要な特権の使用の監査](#重要な特権の使用の監査)
  - [システム](#システム)
    - [その他のシステム イベントの監査](#その他のシステム-イベントの監査)
    - [セキュリティ状態の変更の監査](#セキュリティ状態の変更の監査)
    - [セキュリティ システムの拡張の監査](#セキュリティ-システムの拡張の監査)
    - [システムの整合性の監査](#システムの整合性の監査)
  - [グローバル オブジェクト アクセスの監査](#グローバル-オブジェクト-アクセスの監査)

# Notes about configuring Security log auditing

* You can configure the Security log audit policies with Group Policy at an organizational level, with the Local Security Policy Editor (`gpedit.msc`) for standalone machines, or use scripts to configure them with the built-in `auditpol` command.
* You should always enable Security log auditing at the sub-category level (`コンピューターの設定\Windowsの設定\Securityの設定\監査ポリシー詳細な構成\システム監査ポリシー` in Group Policy) instead of the broad category level as the latter will usually enable too many events and will override any granular settings you made at the sub-category level.
* There are sub-categories and event IDs that are in this documentation but not actually used or are not needed for investigations. Only the important ones that you should enable are listed.
* You cannot turn on or off specific event IDs, only sub-categories at the most granular level. This is unfortunate as sometimes there will be a couple of noisy event IDs that you can not disable unless you disable the entire sub-category.
* The number of sigma rules were taken at 2022/09/24. Be aware that even if there are few or no sigma rules for a certain event, it does not mean that the event is not important.

# Security Event Log Categories and Event IDs

## アカウント ログオン

### 資格情報の確認の監査

ボリューム: NTLM の使用状況に依存. おそらくドメインコントローラーでは高、クライアントとサーバでは低.

規定値: `クライアントOS: 未構成` | `サーバーOS: 成功`

推奨値: `成功と失敗`

Notable Sigma rules:
* `Metasploit SMB Authentication`: Detect when someone is running Metasploit on your network.
* `Valid Users Failing to Authenticate from Single Source Using NTLM`: Password guessing.
* `Invalid Users Failing To Authenticate From Single Source Using NTLM`: Username guessing.
* `Failed Logins with Different Accounts from Single Source System`: Password spraying.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4776 | コンピューターがアカウントの資格情報の確認を試行しました。 | 5 | The original event messages says it is for DCs only but this event gets logged for client OS local authentication as well. | 

### Kerberos 認証サービスの監査

**Note: Enable only for Domain Controllers**

ボリューム: 高

規定値: `クライアントOS: 未構成` | `サーバーOS: 成功`

推奨値: `クライアントOS: 未構成` | `サーバーOS: 成功と失敗`

Notable Sigma rules:
* `(4768) PetitPotam Suspicious Kerberos TGT Request`
* `(4768) Disabled Users Failing To Authenticate From Source Using Kerberos`
* `(4768) Invalid Users Failing To Authenticate From Source Using Kerberos`: Username guessing.
* `(4771) Valid Users Failing to Authenticate From Single Source Using Kerberos`: Password guessing.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4768 | Kerberos 認証チケット (TGT) が要求されました。 | 3 | |
| 4771 | Kerberos 事前認証に失敗しました。 | 1 | |
| 4772 | Kerberos 認証チケットの要求に失敗しました。 | 0 | |

### Kerberos サービス チケット操作の監査

**Note: Enable only for Domain Controllers**

ボリューム: 高

規定値: `クライアントOS: 未構成` | `サーバーOS: 成功`

推奨値: `クライアントOS: 未構成` | `サーバーOS: 成功と失敗`

Notable Sigma rule:
* `(4769) Suspicious Kerberos RC4 Ticket Encryption`: Detects service ticket requests using RC4 encryption. This could be for Kerberoasting (password cracking) or just older systems using legacy encryption.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4769 | Kerberos サービス チケットが要求されました。 | 1 | |
| 4770 | Kerberos サービス チケットが更新されました。 | 0 | |
| 4773 | Kerberos サービス チケットの要求に失敗しました。 | 0 | |

## アカウントの管理

### コンピューター アカウントの管理の監査

ボリューム: ドメインコントローラーでは低

規定値: `クライアントOS: 未構成` | `サーバーOS: 成功`

推奨値: `成功と失敗`

Notable Sigma rule:
* `Possible DC Shadow`: Detects DCShadow via create new SPN.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4741 | コンピューター アカウントが作成されました。 | 0 | |
| 4742 | コンピューター アカウントが変更されました。 | 1 | |
| 4743 | コンピューター アカウントが削除されました。 | 0 | |

### その他のアカウント管理イベントの監査

ボリューム: 通常は低.

規定値: `未構成`

推奨値: `成功と失敗`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4782 | アカウントがアクセスしたパスワード ハッシュ。 | 0 | Generated on a DC during password migration of an account using the AD Migration Toolkit or attackers trying to access password hashes. |
| 4793 | パスワード ポリシーを確認する API が呼び出されました。 | 0 | Generated during password resets or attackers checking the password policy. |

### セキュリティ グループの管理の監査

A "security-enabled" group is a group that you can assign access permissions (ACLs). The other type is a Distribution Group, which is "security-disabled" and cannot be assigned access permissions. Since security-enabled groups are most common, we will refer to them simply as "groups". For example, `Local Group Created`, instead of `A security-enabled local group was created.`.

A domain local group is a security or distribution group that can contain universal groups, global groups, other domain local groups from its own domain, and accounts from any domain in the forest. You can give domain local security groups rights and permissions on resources that reside only in the same domain where the domain local group is located.

A global group is a group that can be used in its own domain, in member servers and in workstations of the domain, and in trusting domains. In all those locations, you can give a global group rights and permissions and the global group can become a member of local groups. However, a global group can contain user accounts that are only from its own domain.

A universal group is a security or distribution group that contains users, groups, and computers from any domain in its forest as members. You can give universal security groups rights and permissions on resources in any domain in the forest.

ボリューム: 低

規定値: `成功`

推奨値: `成功と失敗`

Notable Sigma rules:
* `User Added to Local Administrators`
* `Operation Wocao Activity`: Detects China-based cyber espionage.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4731 | セキュリティが有効なローカル グループが作成されました。 | 0 | |
| 4732 | セキュリティが有効なローカル グループにメンバーが追加されました。 | 1 | |
| 4733 | セキュリティが有効なローカル グループのメンバーが削除されました。 | 0 | |
| 4734 | セキュリティが有効なローカル グループが削除されました。 | 0 | |
| 4764 | グループの種類が変更されました。 | 0 | |
| 4799 | セキュリティが有効なローカル グループ メンバーシップが列挙されました。 | 1 | |
| 4727 | セキュリティが有効なグローバル グループが作成されました。 | 0 | |
| 4737 | セキュリティが有効なグローバル グループが変更されました。 | 0 | |
| 4728 | セキュリティが有効なグローバル グループにメンバーが追加されました。 | 0 | |
| 4729 | セキュリティが有効なグローバル グループのメンバーが削除されました。 | 0 | |
| 4730 | セキュリティが有効なグローバル グループが削除されました。 | 0 | |
| 4754 | セキュリティが有効なユニバーサル グループが作成されました。 | 0 | |
| 4755 | セキュリティが有効なユニバーサル グループが変更されました。 | 0 | |
| 4756 | セキュリティが有効なユニバーサル グループにメンバーが追加されました。 | 0 | |
| 4757 | セキュリティが有効なユニバーサル グループのメンバーが削除されました。 | 0 | |
| 4758 | セキュリティが有効なユニバーサル グループが削除されました。 | 0 | |

### ユーザー アカウントの管理の監査

ボリューム: 低

規定値: `成功`

推奨値: `成功と失敗`

Notable Sigma rules:
* `Hidden Local User Creation`: Detects hidden user accounts most likely used as a backdoor account.
* `Suspicious Windows ANONYMOUS LOGON Local Account Created`
* `Local User Creation`
* `Active Directory User Backdoors`
* `Weak Encryption Enabled and Kerberoast`
* `Addition of SID History to Active Directory Object`: An attacker can use the SID history attribute to gain additional privileges.
* `Possible Remote Password Change Through SAMR`: Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser().
* `Suspicious Computer Account Name Change CVE-2021-42287`: Detects the renaming of an existing computer account to a account name that doesn't contain a $ symbol as seen in attacks against CVE-2021-42287
* `Password Change on Directory Service Restore Mode (DSRM) Account`: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4720 | ユーザー アカウントが作成されました。 | 3 | |
| 4722 | ユーザー アカウントが有効化されました。 | 0 | |
| 4723 | アカウントのパスワードの変更が試行されました。 | 0 | |
| 4724 | アカウントのパスワードのリセットが試行されました。 | 0 | |
| 4725 | ユーザー アカウントが無効化されました。 | 0 | |
| 4726 | ユーザー アカウントが削除されました。 | 0 | |
| 4738 | ユーザー アカウントが変更されました。 | 4 | |
| 4740 | ユーザー アカウントがロックアウトされました。 | 0 | |
| 4765 | SID の履歴がアカウントに追加されました。 | 0 | |
| 4766 | SID の履歴をアカウントに追加できませんでした。 | 0 | |
| 4767 | ユーザー アカウントのロックが解除されました。 | 0 | |
| 4780 | 管理者グループのメンバーのアカウントに ACL が設定されました。 | 0 | |
| 4781 | アカウント名が変更されました。 | 1 | |
| 4794 | ディレクトリ サービス復元モードの管理者パスワードの設定が試行されました。 | 1 | |
| 4798 | ユーザーのローカル グループ メンバーシップが列挙されました。 | 0 | |
| 5376 | 資格情報マネージャーの資格情報がバックアップされました。 | 0 | |
| 5377 | 資格情報マネージャーの資格情報がバックアップから復元されました。 | 0 | |

## 詳細追跡

### PNP アクティビティの監査

This is important if you want to track physical attacks (Rubber Ducky, etc..) or someone exfiltrating data via USB devices.

ボリューム: 通常は低

規定値: `未構成`

推奨値: `成功と失敗`

Notable Sigma rule:
* `(6416) External Disk Drive Or USB Storage Device`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 6416 | 新しい外部デバイスがシステムに認識されました。 | 1 | |
| 6419 | デバイスを無効にするよう要求されました。 | 0 | |
| 6420 | デバイスが無効になりました。 | 0 | |
| 6421 | デバイスを有効にするよう要求されました。 | 0 | |
| 6422 | デバイスが有効になりました。 | 0 | |
| 6423 | このデバイスのインストールはシステム ポリシーで許可されていません。 | 0 | |
| 6424 | このデバイスのインストールは、ポリシーによって禁止された後、許可されました。 | 0 | |

### プロセス作成の監査

Note: A seperate setting needs to be enabled to log command line information which is extremely important. `コンピューターの設定\Windowsの設定\管理用テンプレート\システム\プロセス作成の監査\プロセス作成イベントにコマンドラインを含める` in Group Policy.

If you do not have Sysmon installed and configured to monitor Process Creation, then you should enable this as about half os Sigma's detection rules rely on process creation with command line options enabled.

ボリューム: 高

規定値: `未構成`

推奨値: `成功と失敗` Sysmonを設定していない場合

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4688 | 新しいプロセスが作成されました。 | 902 | |
| 4696 | プライマリ トークンがプロセスに割り当てられました。 | 0 | |

### プロセス終了の監査

You may want to keep this off to save file space.

ボリューム: 高

規定値: `未構成`

推奨値: `未構成` プロセスを追跡したい場合は除く

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4689 | プロセスが終了しました。 | 1 | |

### RPC (Remote Procedure Call) イベントの監査

ボリューム: RPCサーバでは高

規定値: `未構成`

推奨値: `不明。要テスト`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 5712 | リモート プロシージャ コール (RPC) が試行されました。 | 0 | Logged when inbound RPC connection is made. |

### トークン権限の調整を監査する

ボリューム: 高

規定値: `未構成`

推奨値: `不明。要テスト`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4703 | ユーザー権限が調整されました。 | 0 | |

## DS (ディレクトリ サービス) アクセス

**Note: Enable only for Domain Controllers**

### ディレクトリ サービス アクセスの監査

ボリューム: AD DSロールサービス実行中のサーバーでは高

規定値: `クライアントOS: 未構成` | `サーバーOS: 成功`

推奨値: `クライアントOS: 未構成` | `ADDSサーバー: 成功と失敗`

Notable Sigma rules:
* `AD Object WriteDAC Access`
* `Active Directory Replication from Non Machine Account`
* `AD User Enumeration`: Detects access to a domain user from a non-machine account. (Requires the "Read all properties" permission on the user object to be audited for the "Everyone" principal.)
* `DPAPI Domain Backup Key Extraction`: Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers.
* `WMI Persistence`: Detects malware that autostarts via WMI.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4661 | オブジェクトに対するハンドルが要求されました。 | 2 | |
| 4662 | オブジェクトに対して操作が実行されました。 | 6 | |

### ディレクトリ サービスの変更の監査

ボリューム: ドメインコントローラーでは高

規定値: `未構成`

推奨値: `クライアントOS: 未構成` | `ADDSサーバー: 成功と失敗`

Notable Sigma rules:
* `Powerview Add-DomainObjectAcl DCSync AD Extend Right`: Backdooring domain object to grant the rights associated with DCSync to a regular user or machine account.
* `Active Directory User Backdoors`: Detects scenarios where one can control another users or computers account without having to use their credentials.
* `Possible DC Shadow`
* `Suspicious LDAP-Attributes Used`: Detects LDAPFragger, a C2 tool that lets attackers route Cobalt Strike beacon data over LDAP attributes.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 5136 | ディレクトリ サービス オブジェクトが変更されました。 | 6 | |
| 5137 | ディレクトリ サービス オブジェクトが作成されました。 | 0 | |
| 5138 | ディレクトリ サービス オブジェクトが復元されました。 | 0 | |
| 5139 | ディレクトリ サービス オブジェクトを移動しました。 | 0 | |
| 5141 | ディレクトリ サービス オブジェクトが削除されました。 | 0 | |

## ログオン/ログオフ

### アカウント ロックアウトの監査

ボリューム: 低

規定値: `成功`

推奨値: `成功と失敗`

Notable Sigma rules:
* `Scanner PoC for CVE-2019-0708 RDP RCE Vuln`: Detects scans for the BlueKeep vulnerability.
* `Failed Logon From Public IP`
* `Multiple Users Failing to Authenticate from Single Process`
* `Multiple Users Remotely Failing To Authenticate From Single Source`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4625 | アカウントがログオンに失敗しました。 | 4 | |

### グループ メンバーシップの監査

ボリューム: 
ユーザーのグループ メンバーシップに関するログをログオンごとに追加

規定値: `未構成`

推奨値: ACSCは`成功と失敗`を推奨。ただし、ユーザーが属するグループを簡単に検索できる場合、この設定はおそらく不要

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4627 | グループ メンバーシップ情報。 | 0 | Shows what group a user belongs to when they log in. |

### ログオフの監査

ボリューム: 高

規定値: `成功`

推奨値: `成功`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4634 | アカウントがログオフしました。 | 0 | |
| 4647 | ユーザー開始のログオフ | 0 | |

### ログオンの監査

ボリューム: クライアントでは低、ドメインコントローラーやネットワークサーバでは中

規定値: `クライアントOS: 成功` | `サーバーOS: 成功と失敗`

推奨値: `成功と失敗`

Notable Sigma rules:
* `Admin User Remote Logon`
* `Successful Overpass the Hash Attempt`
* `Pass the Hash Activity`
* `RDP Login from Localhost`
* `Login with WMI`
* `KrbRelayUp Attack Pattern`
* `RottenPotato Like Attack Pattern`
* `Failed Logon From Public IP`
* `Suspicious Remote Logon with Explicit Credentials`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4624 | アカウントが正常にログオンしました。 | 11 | |
| 4625 | アカウントがログオンに失敗しました。 | 4 | |
| 4648 | 明示的な資格情報を使用してログオンが試行されました。 | 2 | |

### その他のログオン/ログオフ イベントの監査

ボリューム: 低

規定値: `未構成`

推奨値: `成功と失敗`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4649 | 再生攻撃が検出されました。 | 0 | |
| 4778 | セッションは Window Station に再接続しました。 | 0 | Logged at source for RDP or Fast User Switching. |
| 4779 | セッションは Window Station から切断されました。 | 0 | Logged at source for RDP or Fast User Switching. |
| 4800 | ワークステーションがロックされました。 | 0 | |
| 4801 | ワークステーションのロックが解除されました。 | 0 | |
| 4802 | スクリーン セーバーが起動しました。 | 0 | |
| 4803 | スクリーン セーバーが解除されました。 | 0 | |
| 5378 | 要求された資格情報の委任がポリシーによって許可されませんでした。 | 0 | Usually when WinRM double-hop session was not properly set. |
| 5632 | ワイヤレス ネットワーク認証が要求されました。 | 0 | |
| 5633 | ワイヤード (有線) ネットワーク認証が要求されました。 | 0 | |

### 特殊なログオンの監査

"Special groups" and "Special Privileges" can be thought of as Administrator groups or privileges.

ボリューム: クライアントでは低。ドメインコントローラーやネットワークサーバでは中


規定値: `成功`

推奨値: `成功と失敗`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4672 | 新しいログオンに特権が割り当てられました。 | 0 | |
| 4964 | 特殊グループが新しいログオンに割り当てられました。 | 0 | |

## オブジェクト アクセス

### 証明書サービスの監査

**Note: Enable only for servers providing AD CS role services.**

ボリューム: 低から中

規定値: `未構成`

推奨値: `成功と失敗`(AD CS ロールサーバー).

Notable Sigma rules:
* `ADCS Certificate Template Configuration Vulnerability with Risky EKU`
* `ADCS Certificate Template Configuration Vulnerability`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4898 | 証明書サービスがテンプレートを読み込みました。 | 2 | |

**Note: Many event IDs are enabled. Only the one with sigma rules is shown above.**

### 詳細なファイル共有の監査

ボリューム: Very high for file servers and DCs, however, may be necessary if you want to track who is accessing what files as well as detect various lateral movement.

規定値: `未構成`

推奨値: `未構成` ノイズが多くなるが、可能であれば有効

Notable Sigma rules:
* `Remote Task Creation via ATSVC Named Pipe`
* `Persistence and Execution at Scale via GPO Scheduled Task`
* `Impacket PsExec Execution`
* `Possible Impacket SecretDump Remote Activity`
* `First Time Seen Remote Named Pipe`
* `Possible PetitPotam Coerce Authentication Attempt`
* `Suspicious Access to Sensitive File Extensions`
* `Transferring Files with Credential Data via Network Shares`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 5145 | クライアントに必要なアクセスを付与できるかどうかについて、ネットワーク共有オブジェクトがチェックされました。 | 17 | There are no SACLs (System Access Control Lists) for shared folders so everything is logged. |

### ファイル共有の監査

ボリューム: ファイルサーバーやドメインコントローラーでは高

規定値: `未構成`

推奨値: `成功と失敗`

Notable Sigma rule:
* `(5140) Access to ADMIN$ Share`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 5140 | ネットワーク共有オブジェクトにアクセスしました。 | 1 | Can be combined with File システム auditing to track what files were accessed. |
| 5142 | ネットワーク共有オブジェクトが追加されました。 | 0 | |
| 5143 | ネットワーク共有オブジェクトが変更されました。 | 0 | |
| 5144 | ネットワーク共有オブジェクトが削除されました。 | 0 | |
| 5168 | SMB/SMB2 の SPN チェックに失敗しました。 | 0 | |

### ファイル システムの監査

You need to seperately configure audit permissions on files and/or folders in order for access to be logged. 
For example, by right-clicking, opening Properties, Security tab, Advanced, Auditing tab and then adding a Principal and what permissions to monitor.
It is recommended only to monitor access to sensitive files as there will be too much noise if too many files are enabled for logging.

ボリューム: SACLルールに依存

規定値: `未構成`

推奨値: 機密ファイルの SACL を有効にする

Notable Sigma rules:
* `(4663) ISO Image Mount`
* `(4663) Suspicious Teams Application Related ObjectAcess Event`: Detects access to MS Teams authentication tokens.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトに対するハンドルが要求されました。 | 0 | Could fail if the process does not have the right permissions. |
| 4658 | オブジェクトに対するハンドルが閉じました。 | 0 | |
| 4660 | オブジェクトが削除されました。 | 0 | |
| 4663 | オブジェクトへのアクセスが試行されました。 | 2 | Differs from 4656 in that there are only success events. |
| 4664 | ハード リンクの作成が試行されました。 | 0 | |
| 4670 | オブジェクトのアクセス許可が変更されました。 | 0 | |
| 4985 | トランザクションの状態が変更されました。 | 0 | Used for Transaction Manager and not relevent for security. |
| 5051 | ファイルが仮想化されました。 | 0 | Rarely occurs during LUAFV virtualization. Not relevent for security. |


**Note: EID 4656, 4658, 4660, 4663, 4670 are also used for access to registry and kernel objects as well as removable storage access but need to be configured seperately.** 

### フィルタリング プラットフォームの接続の監査

Logs when WFP (Windows Filtering Platform) allows or blocks port bindings and network connections.

ボリューム: 高

規定値: `未構成`

推奨値: `成功と失敗` 十分なディスクスペースがあり、Sysmonでネットワーク接続を監視していない場合。 ただし、この設定により大量のイベントが発生します。

Notable Sigma rules:
* `(5156) Enumeration via the Global Catalog`: To detect Bloodhound and similar tools.
* `(5156) RDP over Reverse SSH Tunnel WFP`
* `(5156) Remote PowerShell Sessions Network Connections (WinRM)`
* `(5156) Suspicious Outbound Kerberos Connection`: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 5031 | Windows ファイアウォールが、ネットワーク上の着信接続のアプリケーションによる受け入れをブロックしました。 | 0 |  |
| 5150 | Windows フィルタリング プラットフォームによってパケットがブロックされました。 | 0 | |
| 5151 | Windows フィルタリング プラットフォームのより制約のあるフィルターによってパケットがブロックされました。 | 0 | |
| 5154 | Windows フィルターリング プラットフォームで、アプリケーションまたはサービスによるポートでの着信接続のリッスンが許可されました。 | 0 | |
| 5155 | Windows フィルターリング プラットフォームで、アプリケーションまたはサービスによるポートでの着信接続のリッスンがブロックされました。  | 0 | |
| 5156 |  Windows フィルターリング プラットフォームで、接続が許可されました。 | 4 | |
| 5157 | Windows フィルターリング プラットフォームで、接続がブロックされました。 | 0 | |
| 5158 | Windows フィルターリング プラットフォームで、ローカル ポートへのバインドが許可されました。 | 0 | |
| 5159 | Windows フィルターリング プラットフォームで、ローカル ポートへのバインドがブロックされました。 | 0 | |

### フィルタリング プラットフォーム パケットの破棄の監査

ボリューム: 高

規定値: `未構成`

推奨値: `成功と失敗` 十分なディスクスペースがあり、Sysmonでネットワーク接続を監視していない場合。 ただし、この設定により大量のイベントが発生します

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 5152 | Windows フィルターリング プラットフォームによってパケットがブロックされました。 | 0 |  |
| 5153 | Windows フィルターリング プラットフォームのより制約のあるフィルターによってパケットがブロックされました。 | 0 |  |

### カーネルオブジェクトの監査

Only kernel objects with a matching SACL generate security audit events. You can enable auditing of all kernel objects at `コンピューターの構成\Windowsの設定\セキュリティの設定\ローカルポリシー\セキュリティ オプション\監査: グローバル システム オブジェクトへのアクセスを監査する`, however, it is not recommended as you will probably generate too many unneeded events. It is recommended to only enable logging for events that you have detection rules for.

ボリューム: グローバル システム オブジェクトへのアクセスを監査するが有効な場合、高 

規定値: `未構成`

推奨値: ACSCでは`成功と失敗`が推奨。しかし、 この設定により、大量の `4663: オブジェクトへのアクセスが試行されました。` イベントが発生します。

Notable Sigma rules:
* `(4656) Generic Password Dumper Activity on LSASS`
* `(4663) Suspicious Multiple File Rename Or Delete Occurred`: Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may indicate ransomware activity).

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトに対するハンドルが要求されました。 | 4 |  |
| 4658 | オブジェクトに対するハンドルが閉じました。 | 0 |  |
| 4660 | オブジェクトが削除されました。 | 0 |  |
| 4663 | オブジェクトへのアクセスが試行されました。  | 2 |  |

**Note: EID 4656, 4658, 4660, 4663 are also used for access to registry and file system objects as well as removable storage access but need to be configured seperately.** 

### その他のオブジェクト アクセス イベントの監査

It is important to enable as malware will often abuse tasks for persistence and lateral movement.

ボリューム: 低

規定値: `未構成`

推奨値: `成功と失敗`

Notable Sigma rules:
* `(4698) Rare Schtasks Creations`: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code.
* `(4699) Scheduled Task Deletion`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4691 | オブジェクトへの間接アクセスが要求されました。 | 0 |  |
| 4698 | スケジュールされたタスクが作成されました。 | 2 | |
| 4699 | スケジュールされたタスクが削除されました。 | 1 | |
| 4700 | スケジュールされたタスクが有効になりました。 | 0 | |
| 4701 | スケジュールされたタスクが無効になりました。 | 1 | |
| 4702 | スケジュールされたタスクがアップデートされました。 | 0 | |
| 5148 | Windows フィルタリング プラットフォームが DoS 攻撃を検知し、防御モードに移行しました。この攻撃に関連するパケットは破棄されます。 | 0 |  |
| 5149 | DoS 攻撃が沈静化したため、通常の処理を再開します。 | 0 |  |
| 5888 | COM+ カタログのオブジェクトが変更されました。 | 0 |  |
| 5889 | COM+ カタログからオブジェクトが削除されました。 | 0 |  |
| 5890 | COM+ カタログにオブジェクトが追加されました。 | 0 |  |

### レジストリの監査

Many attacks and malware use the registry so it is a great place for evidence, however, it is difficult to only log only what is needed for detection and if you enable all registry access globally, there will be extreme volume of events and possible performance degredation.

ボリューム: SACLの設定に依存する

規定値: `未構成`

推奨値: 監視するレジストリ キーのみに SACL を設定する

Notable Sigma rules:
* `(4656) SAM Registry Hive Handle Request`: Attackers will try to access the SAM registry hive to obtain password hashes.
* `(4656) SCM Database Handle Failure`: Detects non-system users failing to get a handle of the SCM database.
* `(4657) COMPlus_ETWEnabled Registry Modification`: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
* `(4657) NetNTLM Downgrade Attack`
* `(4657) Sysmon Channel Reference Deletion`: Potential threat actor tampering with Sysmon manifest and eventually disabling it.
* `(4657) Creation of a Local Hidden User Account by Registry`
* `(4657) UAC Bypass via Sdclt`
* `(4657) Disable Security Events Logging Adding Reg Key MiniNt`
* `(4657) PrinterNightmare Mimimkatz Driver Name`
* `(4657) Security Support Provider (SSP) Added to LSA Configuration`: Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.
* `(4657) Suspicious Run Key from Download`
* `(4657) Suspicious Camera and Microphone Access`
* `(4657) Usage of Sysinternals Tools`
* `(4657) Common Autorun Keys Modification`
* `(4657) Disable Sysmon Event Logging Via Registry`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトに対するハンドルが要求されました。 | 2 |  |
| 4657 | レジストリ値が変更されました。 | 182 |  |
| 4658 | オブジェクトに対するハンドルが閉じました。 | 0 |  |
| 4660 | オブジェクトが削除されました。  | 0 |  |
| 4663 | オブジェクトへのアクセスが試行されました。 | 0 |  |
| 4670 | オブジェクトのアクセス許可が変更されました。 | 0 |  |

**Note: EID 4656, 4658, 4660, 4663, 4670 are also used for access to kernel and file system objects as well as removable storage access but need to be configured seperately.** 

### リムーバブル記憶域の監査

This logs all file access to removable storage regardless of SACL settings.
You may want to enable to track employees exfiltrating data via USB storage.

ボリューム: リムーバブル ストレージの使用量に依存

規定値: `未構成`

推奨値: `成功と失敗` 外部デバイスの使用状況を監視したい場合

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトに対するハンドルが要求されました。 | 0 |  |
| 4658 | オブジェクトに対するハンドルが閉じました。 | 0 |  |
| 4663 | オブジェクトへのアクセスが試行されました。 | 0 |  |

**Note: EID 4656, 4658, 4663 are also used for access to registry, kernel and file system objects but need to be configured seperately.** 

### SAMの監査

This will log attempts to access Security Account Manager (SAM) objects, such as user and computer accounts, groups, security descriptors, etc...

ボリューム: ドメインコントローラーでは高

規定値: `未構成`

推奨値: `成功と失敗` ノイズが多すぎる場合、事前にテストが必要

Notable Sigma rules:
* `(4661) Reconnaissance Activity`: Detects activity such as "net user administrator /domain" and "net group domain admins /domain".
* `(4661) AD Privileged Users or Groups Reconnaissance`: Detect privileged users or groups recon based on 4661 eventid and known privileged users or groups SIDs.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4661 | オブジェクトに対するハンドルが要求されました。 | 2 |  |

## ポリシーの変更

### 監査ポリシーの変更の監査

Changes to audit policy that are audited include:
* Changing permissions and audit settings on the audit policy object (by using “auditpol /set /sd” command).
* Changing the system audit policy.
* Registering and unregistering security event sources.
* Changing per-user audit settings.
* Changing the value of CrashOnAuditFail.
* Changing audit settings on an object (for example, modifying the system access control list (SACL) for a file or registry key).
* Changing anything in the Special Groups list.

ボリューム: 低

規定値: `成功`

推奨値: `成功と失敗`

Notable Sigma rule:
* `(4719) Disabling Windows Event Auditing`: Detects anti-forensics via local GPO policy.
 
| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4715 | オブジェクトの監査ポリシー (SACL) が変更されました。 | 0 | Logged regardless of Audit ポリシーの変更 settings. |
| 4719 | システム監査ポリシーが変更されました。 | 1 | Logged regardless of Audit ポリシーの変更 settings. |
| 4817 | オブジェクトの監査設定が変更されました。 | 0 | Logged regardless of Audit ポリシーの変更 settings. |
| 4902 | ユーザーごとの監査ポリシー テーブルが作成されました。 | 0 | |
| 4904 | セキュリティ イベント ソースの登録が試行されました。 | 0 | |
| 4905 | セキュリティ イベント ソースの登録解除が試行されました。 | 0 | |
| 4906 | CrashOnAuditFail の値が変更されました。| 0 | Logged regardless of Audit ポリシーの変更 settings. |
| 4907 | オブジェクトの監査設定が変更されました。 | 0 | |
| 4908 | 特殊グループのログオン テーブルが変更されました。 | 0 | Logged regardless of Audit ポリシーの変更 settings. |
| 4912 | ユーザーごとの監査ポリシーが変更されました。 | 0 | Logged regardless of Audit ポリシーの変更 settings. |

### 認証ポリシーの変更の監査

Changes made to authentication policy include:
* Creation, modification, and removal of forest and domain trusts.
* Changes to Kerberos policy under Computer Configuration\Windows Settings\Security Settings\Account Policies\Kerberos Policy.
* When any of the following user logon rights is granted to a user or group:
* Access this computer from the network
* Allow logon locally
* Allow logon through Remote Desktop
* Logon as a batch job
* Logon as a service
* Namespace collision, such as when an added trust collides with an existing namespace name.

This setting is useful for tracking changes in domain-level and forest-level trust and privileges that are granted to user accounts or groups.

ボリューム: 低

規定値: `成功`

推奨値: `成功と失敗`

Notable Sigma rule:
* `(4706) Addition of Domain Trusts`: Addition of domains is seldom and should be verified for legitimacy.
 
| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4670 | オブジェクトのアクセス許可が変更されました。 | 0 | |
| 4706 | ドメインに対して新しい信頼が作成されました。 | 1 | |
| 4707 | ドメインに対する信頼が削除されました。 | 0 | |
| 4713 | Kerberos ポリシーが変更されました。 | 0 | |
| 4716 | 信頼される側のドメインの情報が変更されました。 | 0 | |
| 4717 | アカウントに対してシステム セキュリティ アクセスが許可されました。 | 0 | |
| 4718 | アカウントからシステム セキュリティ アクセスが削除されました。 | 0 | |
| 4739 | ドメイン ポリシーが変更されました。 | 0 | |
| 4864 | 名前空間の競合が検出されました。 | 0 | |
| 4865 | 信頼されたフォレスト情報のエントリが追加されました。 | 0 | |
| 4866 | 信頼されたフォレスト情報のエントリが削除されました。 | 0 | |
| 4867 | 信頼されたフォレスト情報のエントリが変更されました。 | 0 | |

### 認可ポリシーの変更の監査

Audits assignment and removal of user rights in user right policies, changes in security token object permission, resource attributes changes and Central Access Policy changes for file system objects.

You can get information related to changes in user rights policies, or changes of resource attributes or Central Access Policy applied to file system objects.
However, if you are using an application or system service that makes changes to system privileges through the AdjustPrivilegesToken API, it is not recommended to enable due to the high volume of events.

ボリューム: 中から高

規定値: `未構成`

推奨値: `不明。要テスト`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4703 | ユーザー権限が調整されました。 | 0 | As of Windows 10, this event is generated by applications and services that dynamically adjust token privileges. An example is Microsoft Endpoint Configuration Manager, which makes WMI queries at recurring intervals generating a large amount of events from the svchost.exe process. |
| 4704 | ユーザー権利が割り当てられました。 | 0 | |
| 4705 | ユーザー権利が削除されました。 | 0 | |
| 4670 | オブジェクトのアクセス許可が変更されました。 | 0 | |
| 4911 | オブジェクトのリソース属性が変更されました。 | 0 | |
| 4913 | オブジェクトの集約型アクセス ポリシーが変更されました。 | 0 | |

### フィルタリング プラットフォーム ポリシーの変更の監査

Audit events generated by changes to the Windows Filtering Platform (WFP), such as the following:
* IPsec services status.
* Changes to IPsec policy settings.
* Changes to Windows Filtering Platform Base Filtering Engine policy settings.
* Changes to WFP providers and engine.

ボリューム: 低

規定値: `未構成`

推奨値: `不明。要テスト`

There are too many events that are enabled with this sub-category to list up and no sigma detection rules that use these event IDs at the moment.

### MPSSVC ルールレベル ポリシーの変更の監査

Audit MPSSVC Rule-Level Policy Change determines whether the operating system generates audit events when changes are made to policy rules for the Microsoft Protection Service (MPSSVC.exe).
The Microsoft Protection Service, which is used by Windows Firewall, is an integral part of the computer’s threat protection against malware. The tracked activities include:
* Active policies when the Windows Firewall service starts.
* Changes to Windows Firewall rules.
* Changes to the Windows Firewall exception list.
* Changes to Windows Firewall settings.
* Rules ignored or not applied by the Windows Firewall service.
* Changes to Windows Firewall Group Policy settings.

Changes to firewall rules are important for understanding the security state of the computer and how well it is protected against network attacks.

ボリューム: 低

規定値: `未構成`

推奨値: `不明。要テスト`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4944 | 次のポリシーは、Windows ファイアウォールの起動時にアクティブでした。| 0 | |
| 4945 | Windows ファイアウォールの起動時に規則が表示されました。 | 0 | |
| 4946 | Windows ファイアウォールの例外の一覧が変更されました。規則が追加されました。 | 0 | |
| 4947 | Windows ファイアウォールの例外の一覧が変更されました。規則が変更されました。 | 0 | |
| 4948 | Windows ファイアウォールの例外の一覧が変更されました。規則が削除されました。 | 0 | |
| 4949 | Windows ファイアウォールの設定が既定値に戻されました。 | 0 | |
| 4950 | Windows ファイアウォールの設定が変更されました。 | 0 | |
| 4951 | 規則のメジャー バージョンが認識されなかったため、Windows ファイアウォールでその規則が無視されました。 | 0 | |
| 4952 | 規則のマイナー バージョン番号が認識されなかったため、Windows ファイアウォールでその規則の一部が無視されました。規則のその他の部分は適用されます。 | 0 | |
| 4953 | Windows ファイアウォールで、解析できなかった規則が無視されました。 | 0 | |
| 4954 | Windows ファイアウォールのグループ ポリシーの設定が変更され、新しい設定が適用されました。 | 0 | |
| 4956 | Windows ファイアウォールでアクティブなプロファイルが変更されました。 | 0 | |
| 4957 | Windows ファイアウォールで次の規則が適用されませんでした。 | 0 | |
| 4958 | このコンピューターで構成されていないアイテムを次の規則が参照しているために、Windows ファイアウォールで規則が適用されませんでした。 | 0 | |

There are no sigma detection rules for this sub-category at the moment.

### その他のポリシー変更イベントの監査

Audit Other Policy Change Events contains events about EFS Data Recovery Agent policy changes, changes in Windows Filtering Platform filter, status on Security policy settings updates for local Group Policy settings, Central Access Policy changes, and detailed troubleshooting events for Cryptographic Next Generation (CNG) operations.

ボリューム: 低

規定値: `未構成`

推奨値: ACSC recommends `成功と失敗`, however, this results in a lot of noise of `5447 (Windows フィルターリング プラットフォームのフィルターが変更されました。)` events being generated.

There are too many events that are enabled with this sub-category to list up and no sigma detection rules that use these event IDs at the moment.

## 特権の使用

### 重要でない特権の使用の監査

Audit Non-Sensitive Privilege Use contains events that show usage of non-sensitive privileges:
* Access Credential Manager as a trusted caller
* Add workstations to domain
* Adjust memory quotas for a process
* Bypass traverse checking
* Change the system time
* Change the time zone
* Create a page file
* Create global objects
* Create permanent shared objects
* Create symbolic links
* Force shutdown from a remote system
* Increase a process working set
* Increase scheduling priority
* Lock pages in memory
* Modify an object label
* Perform volume maintenance tasks
* Profile single process
* Profile system performance
* Remove computer from docking station
* Shut down the system
* Synchronize directory service data

ボリューム: とても高

規定値: `未構成`

推奨値: `未構成`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4673 | 特権のあるサービスが呼び出されました。 | 0 | |
| 4674 | 特権のあるオブジェクトで操作が試行されました。 | 0 | |
| 4985 | トランザクションの状態が変更されました。 | 0 | |

**Note: Non-sensitive and sensitive privilege use events use the same event ID.**

### 重要な特権の使用の監査

Audit Sensitive Privilege Use contains events that show the usage of sensitive privileges:
* Act as part of the operating system
* Back up files and directories
* Restore files and directories
* Create a token object
* Debug programs
* Enable computer and user accounts to be trusted for delegation
* Generate security audits
* Impersonate a client after authentication
* Load and unload device drivers
* Manage auditing and security log
* Modify firmware environment values
* Replace a process-level token
* Take ownership of files or other objects

The use of two privileges, “Back up files and directories” and “Restore files and directories,” generate events only if the `コンピューターの設定\Windowsの設定\Securityの設定\ローカルポリシー\セキュリティ オプション\監査: グローバル システム オブジェクトへのアクセスを監査する` Group Policy setting is enabled on the computer or device. However, it is not recommended to enable this Group Policy setting because of the high number of events recorded.

ボリューム: 高

規定値: `未構成`

推奨値: `成功と失敗. ただし、ノイズが多すぎる可能性があります.`

Notable Sigma rules:
* `(4673) User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'`: The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.
* `(4673) Suspicious Driver Loaded By User`: Detects the loading of drivers via 'SeLoadDriverPrivilege' required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers. This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.
* `(4674) SCM Database Privileged Operation`: Detects non-system users performing privileged operation os the SCM database.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4673 | 特権のあるサービスが呼び出されました。 | 2 | |
| 4674 | 特権のあるオブジェクトで操作が試行されました。 | 1 | |
| 4985 | トランザクションの状態が変更されました。 | 0 | |

**Note: Non-sensitive and sensitive privilege use events use the same event ID.**

## システム

### その他のシステム イベントの監査

Audit Other System Events contains Windows Firewall Service and Windows Firewall driver start and stop events, failure events for these services and Windows Firewall Service policy processing failures:
* Startup and shutdown of the Windows Firewall service and driver.
* Security policy processing by the Windows Firewall service.
* Cryptography key file and migration operations.
* BranchCache events.

ボリューム: 低

規定値: `成功と失敗`

推奨値: `不明。要テスト`

There are too many events that are enabled with this sub-category to list up and no sigma detection rules that use these event IDs at the moment.

### セキュリティ状態の変更の監査

Audit Security State Change contains Windows startup, recovery, and shutdown events, and information about changes in system time.

ボリューム: 低

規定値: `成功`

推奨値: `成功と失敗`

Notable Sigma rule:
* `(4616) Unauthorized System Time Modification`: Detect scenarios where a potentially unauthorized application or user is modifying the system time.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4608 | Windows を起動しています。 | 0 | |
| 4616 | システム時刻が変更されました。 | 1 | |
| 4621 | 管理者が CrashOnAuditFail からシステムを復旧しました。 | 0 | |

### セキュリティ システムの拡張の監査

This policy setting allows you to audit events related to security system extensions or services such as the following:
* A security system extension, such as an authentication, notification, or security package is loaded and is registered with the Local Security Authority (LSA). It is used to authenticate logon attempts, submit logon requests, and any account or password changes. Examples of security system extensions are Kerberos and NTLM.
* A service is installed and registered with the Service Control Manager. The audit log contains information about the service name, binary, type, start type, and service account.

ボリューム: 低、ドメインコントローラーでは高

規定値: `未構成`

推奨値: `成功と失敗`

Notable Sigma rule:
* `(4611) Register new Logon Process by Rubeus`: Detects potential use of Rubeus via registered new trusted logon process.
* `(4697) Invoke-Obfuscation Obfuscated IEX Invocation`
* `(4697) Invoke-Obfuscation Via Use Rundll32`
* `(4697) Invoke-Obfuscation Via Use MSHTA`
* `(4697) CobaltStrike Service Installations`
* `(4697) Credential Dumping Tools Service Execution`
* `(4697) Malicious Service Installations`
* `(4697) Meterpreter or Cobalt Strike Getsystem Service Installation`

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4610 | ローカル セキュリティ機関によって、認証パッケージが読み込まれました。 | 0 | Should be monitored with an allowlist. |
| 4611 | 信頼されたログオン プロセスがローカル セキュリティ機関に登録されています。 | 1 | Should display "System" in the "Subject" field. |
| 4614 | 通知パッケージがセキュリティ アカウント マネージャーにより読み込まれています。 | 0 | |
| 4622 | セキュリティ パッケージがローカル セキュリティ機関によって読み込まれました。 | 0 | |
| 4697 | サービスがシステムにインストールされました。 | 20 | This is the most important event in this sub-category. |

### システムの整合性の監査

Audit System Integrity determines whether the operating system audits events that violate the integrity of the security subsystem:
* Audited events are lost due to a failure of the auditing system.
* A process uses an invalid local procedure call (LPC) port in an attempt to impersonate a client, reply to a client address space, read to a client address space, or write from a client address space.
* A remote procedure call (RPC) integrity violation is detected.
* A code integrity violation with an invalid hash value of an executable file is detected.
* Cryptographic tasks are performed.

According to Microsoft, violations of security subsystem integrity are critical and could indicate a potential security attack.

ボリューム: 低

規定値: `成功と失敗`

推奨値: `成功と失敗`

Currently, there are no sigma rules for this sub-category.

| Event ID | Description | Sigma Rules | Notes |
| :---: | :---: | :---: | :---: |
| 4612 | 監査メッセージをキューに登録するために割り当てられた内部リソースをすべて使用したため、一部の監査が失われました。 | 0 | This is important to monitor. |
| 4615 | LPC ポートの使用が無効です。| 0 |  |
| 4618 | 監視されるセキュリティ イベント パターンが発生しています。 | 0 | This event can only be invoked manually. |
| 4816 | 着信メッセージの解読の際に RPC が整合性違反を検出しました。 | 0 |  |
| 5038 | コードの整合性によって、ファイルのイメージ ハッシュが有効でないと判断されました。このファイルは、無許可の変更によって破損しているか、無効なハッシュがディスク デバイス エラーの可能性を示している場合があります。 | 0 |  |
| 5056 | 暗号化セルフ テストが実行されました。 | 0 |  |
| 5057 | 暗号化のプリミティブ操作に失敗しました。 | 0 |  |
| 5060 | 検証操作に失敗しました。 | 0 |  |
| 5061 | 暗号化操作。 | 0 |  |
| 5062 | カーネルモードの暗号化セルフ テストが実行されました。 | 0 |  |
| 6281 | コードの整合性によって、イメージ ファイルのページ ハッシュが有効でないと判断されました。 このファイルはページ ハッシュを使用せず正しくない方法で署名されたか、無許可の変更によって破損した可能性があります。無効なハッシュはディスク デバイス エラーの可能性を示している場合もあります。 | 0 |  |
| 6410 | コードの整合性によって、ファイルがプロセスに読み込むためのセキュリティ要件を満たしていないと判断されました。 | 0 |  |

## グローバル オブジェクト アクセスの監査

You can configure all `File system` and `Registry` access to be recorded here but it is not recommended due to the very high amount of logs you will generate.
