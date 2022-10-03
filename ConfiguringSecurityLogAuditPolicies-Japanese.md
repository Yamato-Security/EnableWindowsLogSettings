<div align="center">
 <h1>
    Securityログ設定について
 </h1>
 [<a href="ConfiguringSecurityLogAuditPolicies.md">English</a>] | [<b>日本語</b>]
</div>
<p>

**現在、日本語版はできていません。和訳したい方を募集しています！**

# 目次

- [目次](#目次)
- [セキュリティログ監査の設定に関する注意事項](#セキュリティログ監査の設定に関する注意事項)
- [SecurityイベントログのカテゴリとイベントID](#securityイベントログのカテゴリとイベントid)
  - [アカウントログオン](#アカウントログオン)
    - [資格情報の確認](#資格情報の確認)
    - [Kerberos認証サービス](#kerberos認証サービス)
    - [Kerberosサービスチケット操作](#kerberosサービスチケット操作)
  - [アカウントの管理](#アカウントの管理)
    - [コンピュータアカウントの管理](#コンピュータアカウントの管理)
    - [その他のアカウント管理イベント](#その他のアカウント管理イベント)
    - [セキュリティグループの管理](#セキュリティグループの管理)
    - [ユーザーアカウントの管理](#ユーザーアカウントの管理)
  - [詳細追跡](#詳細追跡)
    - [PNPアクティビティ](#pnpアクティビティ)
    - [プロセス作成](#プロセス作成)
    - [プロセス終了](#プロセス終了)
    - [RPCイベント](#rpcイベント)
    - [トークン権限の調整](#トークン権限の調整)
  - [DS(ディレクトリサービス)アクセス](#dsディレクトリサービスアクセス)
    - [ディレクトリサービスアクセス](#ディレクトリサービスアクセス)
    - [ディレクトリサービスの変更](#ディレクトリサービスの変更)
  - [ログオン/ログオフ](#ログオンログオフ)
    - [アカウントロックアウト](#アカウントロックアウト)
    - [グループメンバーシップ](#グループメンバーシップ)
    - [ログオフ](#ログオフ)
    - [ログオン](#ログオン)
    - [その他のログオン/ログオフイベント](#その他のログオンログオフイベント)
    - [特殊なログオン](#特殊なログオン)
  - [オブジェクトアクセス](#オブジェクトアクセス)
    - [証明書サービス](#証明書サービス)
    - [詳細なファイル共有](#詳細なファイル共有)
    - [ファイル共有](#ファイル共有)
    - [ファイルシステム](#ファイルシステム)
    - [フィルタリングプラットフォームの接続](#フィルタリングプラットフォームの接続)
    - [フィルタリングプラットフォームパケットの破棄](#フィルタリングプラットフォームパケットの破棄)
    - [カーネルオブジェクト](#カーネルオブジェクト)
    - [その他のオブジェクトアクセスイベント](#その他のオブジェクトアクセスイベント)
    - [レジストリ](#レジストリ)
    - [リムーバブル記憶域](#リムーバブル記憶域)
    - [SAM](#sam)
  - [ポリシーの変更](#ポリシーの変更)
    - [監査ポリシーの変更](#監査ポリシーの変更)
    - [認証ポリシーの変更](#認証ポリシーの変更)
    - [承認ポリシーの変更](#承認ポリシーの変更)
    - [フィルタリングプラットフォームポリシーの変更](#フィルタリングプラットフォームポリシーの変更)
    - [MPSSVCルールレベルポリシーの変更](#mpssvcルールレベルポリシーの変更)
    - [その他のポリシー変更イベント](#その他のポリシー変更イベント)
  - [特権の使用](#特権の使用)
    - [重要でない特権の使用](#重要でない特権の使用)
    - [重要な特権の使用](#重要な特権の使用)
  - [システム](#システム)
    - [その他のシステムイベント](#その他のシステムイベント)
    - [セキュリティ状態の変更](#セキュリティ状態の変更)
    - [セキュリティシステムの拡張](#セキュリティシステムの拡張)
    - [システムの整合性](#システムの整合性)
  - [グローバルオブジェクトアクセス](#グローバルオブジェクトアクセス)

# セキュリティログ監査の設定に関する注意事項

* You can configure the Security log audit policies with Group Policy at an organizational level, with the Local Security Policy Editor (`gpedit.msc`) for standalone machines, or use scripts to configure them with the built-in `auditpol` command.
* You should always enable Security log auditing at the sub-category level (`Computer Configuration > Windows Settings > Security Settings > Advanced security audit policy settings > System Audit Policies` in Group Policy) instead of the broad category level as the latter will usually enable too many events and will override any granular settings you made at the sub-category level.
* There are sub-categories and イベントIDs that are in this documentation but not actually used or are not needed for investigations. Only the important ones that you should enable are listed.
* You cannot turn on or off specific イベントIDs, only sub-categories at the most granular level. This is unfortunate as sometimes there will be a couple of noisy イベントIDs that you can not disable unless you disable the entire sub-category.
* The number of sigma rules were taken at 2022/09/24. Be aware that even if there are few or no sigma rules for a certain event, it does not mean that the event is not important.

# SecurityイベントログのカテゴリとイベントID

## アカウントログオン

### 資格情報の確認

ボリューム: Depends on NTLM usage. Could be high on DCs and low on clients and servers.

デフォルトの設定: `クライアントOS: 監査なし` | `サーバOS: 成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `Metasploit SMB Authentication`: Detect when someone is running Metasploit on your network.
* `Valid Users Failing to Authenticate from Single Source Using NTLM`: パスワード推測攻撃
* `Invalid Users Failing To Authenticate From Single Source Using NTLM`: ユーザ名の推測
* `Failed Logins with Different Accounts from Single Source System`: パスワードスプレー攻撃

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4776 | ローカルユーザアカウントのNTLM認証 | 5 | The original event messages says it is for DCs only but this event gets logged for クライアントOS local authentication as well. | 

### Kerberos認証サービス

**注意：ドメインコントローラのみ有効**

ボリューム: 高

デフォルトの設定: `クライアントOS: 監査なし` | `サーバOS: 成功`

推奨設定: `クライアントOS: 監査なし` | `サーバOS: 成功と失敗`

Sigmaルールの例:
* `(4768) PetitPotam Suspicious Kerberos TGT Request`
* `(4768) Disabled Users Failing To Authenticate From Source Using Kerberos`
* `(4768) Invalid Users Failing To Authenticate From Source Using Kerberos`: ユーザ名の推測
* `(4771) Valid Users Failing to Authenticate From Single Source Using Kerberos`: パスワード推測攻撃

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4768 | TGTが要求された | 3 | |
| 4771 | 事前認証に失敗した | 1 | |
| 4772 | Kerberos認証チケット要求が失敗した | 0 | |

### Kerberosサービスチケット操作

**注意：ドメインコントローラのみ有効**

ボリューム: 高

デフォルトの設定: `クライアントOS: 監査なし` | `サーバOS: 成功`

推奨設定: `クライアントOS: 監査なし` | `サーバOS: 成功と失敗`

Sigmaルールの例:
* `(4769) Suspicious Kerberos RC4 Ticket Encryption`: Detects service ticket requests using RC4 encryption. This could be for Kerberoasting (password cracking) or just older systems using legacy encryption.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4769 | Kerberosサービスチケットが要求された | 1 | |
| 4770 | Kerberosサービスチケットが更新された | 0 | 実はTGT更新 |
| 4773 | Kerberos Service Ticket Request Failed | 0 | |

## アカウントの管理

### コンピュータアカウントの管理

ボリューム: Low on DCs.

デフォルトの設定: `クライアントOS: 監査なし` | `サーバOS: 成功のみ`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `Possible DC Shadow`: Detects DCShadow via create new SPN.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4741 | コンピュータアカウントが作成された | 0 | |
| 4742 | コンピューターアカウントが変更された | 1 | |
| 4743 | コンピューターアカウントが削除された | 0 | |

### その他のアカウント管理イベント

ボリューム: 一般的に低い

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4782 | アカウントのパスワードハッシュがアクセスされた | 0 | Generated on a DC during password migration of an account using the AD Migration Toolkit or attackers trying to access password hashes. |
| 4793 | パスワードポリシーチェックAPIが呼び出された | 0 | Generated during password resets or attackers checking the password policy. |

### セキュリティグループの管理

A "security-enabled" group is a group that you can assign access permissions (ACLs). The other type is a Distribution Group, which is "security-disabled" and cannot be assigned access permissions. Since security-enabled groups are most common, we will refer to them simply as "groups". For example, `Local Group Created`, instead of `A security-enabled local group was created.`.

A domain local group is a security or distribution group that can contain universal groups, global groups, other domain local groups from its own domain, and accounts from any domain in the forest. You can give domain local security groups rights and permissions on resources that reside only in the same domain where the domain local group is located.

A global group is a group that can be used in its own domain, in member servers and in workstations of the domain, and in trusting domains. In all those locations, you can give a global group rights and permissions and the global group can become a member of local groups. However, a global group can contain user accounts that are only from its own domain.

A universal group is a security or distribution group that contains users, groups, and computers from any domain in its forest as members. You can give universal security groups rights and permissions on resources in any domain in the forest.

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `User Added to Local Administrators`
* `Operation Wocao Activity`: Detects China-based cyber espionage.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4731 | ローカルグループが作成された | 0 | |
| 4732 | ローカルグループにメンバーが追加された | 1 | |
| 4733 | ローカルグループからメンバーが削除された | 0 | |
| 4734 | ローカルグループが削除された | 0 | |
| 4764 | グループの種類が変更された | 0 | |
| 4799 | ローカルグループメンバーシップが列挙された | 1 | |
| 4727 | グローバルグループが作成された | 0 | |
| 4737 | グローバルグループが変更された | 0 | |
| 4728 | グローバルグループにメンバーが追加された | 0 | |
| 4729 | グローバルグループからメンバーが削除された | 0 | |
| 4730 | グローバルグループが削除された | 0 | |
| 4754 | ユニバーサルグループが作成された | 0 | |
| 4755 | ユニバーサルグループが変更された | 0 | |
| 4756 | ユニバーサルグループにメンバーが追加された | 0 | |
| 4757 | ユニバーサルグループからメンバーが削除された | 0 | |
| 4758 | ユニバーサルグループが削除された | 0 | |

### ユーザーアカウントの管理

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `Hidden Local User Creation`: Detects hidden user accounts most likely used as a backdoor account.
* `Suspicious Windows ANONYMOUS LOGON Local Account Created`
* `Local User Creation`
* `Active Directory User Backdoors`
* `Weak Encryption Enabled and Kerberoast`
* `Addition of SID History to Active Directory Object`: An attacker can use the SID history attribute to gain additional privileges.
* `Possible Remote Password Change Through SAMR`: Detects a possible remote NTLM hash change through SAMR API SamiChangePasswordUser() or SamSetInformationUser().
* `Suspicious Computer Account Name Change CVE-2021-42287`: Detects the renaming of an existing computer account to a account name that doesn't contain a $ symbol as seen in attacks against CVE-2021-42287
* `Password Change on Directory Service Restore Mode (DSRM) Account`: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4720 | ユーザアカウントが作成された | 3 | |
| 4722 | ユーザアカウントが有効になった | 0 | |
| 4723 | パスワードを変更しようとした | 0 | |
| 4724 | パスワードのリセットが試行された | 0 | |
| 4725 | ユーザアカウントが無効になった | 0 | |
| 4726 | ユーザアカウントが削除された | 0 | |
| 4738 | ユーザアカウントが変更された | 4 | |
| 4740 | ユーザアカウントがロックアウトされた | 0 | |
| 4765 | SID History Added To Account | 0 | |
| 4766 | アカウントにSID履歴を追加する試みは失敗した | 0 | |
| 4767 | ユーザアカウントのロックが解除された | 0 | |
| 4780 | 管理者グループのメンバーであるアカウントにACLが設定された | 0 | |
| 4781 | アカウントの名前が変更された | 1 | |
| 4794 | DSRM Administrator Password Set | 1 | |
| 4798 | User's Local Group Membership Enumerated | 0 | |
| 5376 | Credential Manager Credentials Backup | 0 | |
| 5377 | Credential Manager Credentials Restored | 0 | |

## 詳細追跡

### PNPアクティビティ

This is important if you want to track physical attacks (Rubber Ducky, etc..) or someone exfiltrating data via USB devices.

ボリューム: Depends but typically low.

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(6416) External Disk Drive Or USB Storage Device`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 6416 | New External Device | 1 | |
| 6419 | Request To Disable Device | 0 | |
| 6420 | デバイスが無効にされた | 0 | |
| 6421 | Request To Enable Device | 0 | |
| 6422 | デバイスが有効にされた | 0 | |
| 6423 | Device Installation Blocked | 0 | |
| 6424 | Device Installation Allowed After Being Blocked | 0 | |

### プロセス作成

Note: A seperate setting needs to be enabled to log command line information which is extremely important. `Computer Configuration > Windows Settings > Administrative Templates > System > Audit Process Creation > Include command line in process creation events` in Group Policy.

If you do not have Sysmon installed and configured to monitor Process Creation, then you should enable this as about half os Sigma's detection rules rely on process creation with command line options enabled.

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: Sysmonがインストールされていない場合は`成功と失敗`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4688 | プロセス作成 | 902 | |
| 4696 | プライマリトークンがプロセスに割り当てされた | 0 | |

### プロセス終了

You may want to keep this off to save file space.

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `監査なし` unless you want to track the lifespan of processes.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4689 | プロセス終了 | 1 | |

### RPCイベント

ボリューム: High on RPC servers.

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5712 | RPC Attempt | 0 | Logged when inbound RPC connection is made. |

### トークン権限の調整

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4703 | User's Token Changed | 0 | |

## DS(ディレクトリサービス)アクセス

**注意：ドメインコントローラのみ有効**

### ディレクトリサービスアクセス

ボリューム: High on servers running AD DS role services.

デフォルトの設定: `クライアントOS: 監査なし` | `サーバOS: 成功`

推奨設定: `クライアントOS: 監査なし` | `ADDS Server: 成功と失敗`

Sigmaルールの例:
* `AD Object WriteDAC Access`
* `Active Directory Replication from Non Machine Account`
* `AD User Enumeration`: Detects access to a domain user from a non-machine account. (Requires the "Read all properties" permission on the user object to be audited for the "Everyone" principal.)
* `DPAPI Domain Backup Key Extraction`: Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers.
* `WMI Persistence`: Detects malware that autostarts via WMI.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4661 | Handle To Object Requested | 2 | |
| 4662 | Operation Performed On Object | 6 | |

### ディレクトリサービスの変更

ボリューム: High on DCs.

デフォルトの設定: `監査なし`

推奨設定: `クライアントOS: 監査なし` | `ADDS Server: 成功と失敗`

Sigmaルールの例:
* `Powerview Add-DomainObjectAcl DCSync AD Extend Right`: Backdooring domain object to grant the rights associated with DCSync to a regular user or machine account.
* `Active Directory User Backdoors`: Detects scenarios where one can control another users or computers account without having to use their credentials.
* `Possible DC Shadow`
* `Suspicious LDAP-Attributes Used`: Detects LDAPFragger, a C2 tool that lets attackers route Cobalt Strike beacon data over LDAP attributes.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5136 | Directory Service Object Modified | 6 | |
| 5137 | Directory Service Object Created | 0 | |
| 5138 | Directory Service Object Undeleted | 0 | |
| 5139 | Directory Service Object Moved | 0 | |
| 5141 | Directory Service Object Deleted | 0 | |

## ログオン/ログオフ

### アカウントロックアウト

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `Scanner PoC for CVE-2019-0708 RDP RCE Vuln`: Detects scans for the BlueKeep vulnerability.
* `Failed Logon From Public IP`
* `Multiple Users Failing to Authenticate from Single Process`
* `Multiple Users Remotely Failing To Authenticate From Single Source`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4625 | Logon Failed Due To Lockout | 4 | |

### グループメンバーシップ

ボリューム: Adds an extra log about a user's group membership to every logon.

デフォルトの設定: `監査なし`

推奨設定: ACSC recommends `成功と失敗` but this is probably not needed if you can easily lookup what groups a user belongs to.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4627 | グループメンバーシップ情報 | 0 | Shows what group a user belongs to when they log in. |

### ログオフ

ボリューム: 高

デフォルトの設定: `成功`

推奨設定: `成功`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4634 | ログオフ | 0 | |
| 4647 | ユーザがログオフした | 0 | |

### ログオン

ボリューム: Low on clients, medium on DCs or network servers.

デフォルトの設定: `クライアントOS: 成功` | `サーバOS: 成功と失敗`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `Admin User Remote Logon`
* `Successful Overpass the Hash Attempt`
* `Pass the Hash Activity`
* `RDP Login from Localhost`
* `Login with WMI`
* `KrbRelayUp Attack Pattern`
* `RottenPotato Like Attack Pattern`
* `Failed Logon From Public IP`
* `Suspicious Remote Logon with Explicit Credentials`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4624 | ログオン | 11 | |
| 4625 | ログオンに失敗 | 4 | |
| 4648 | 明示的なログオン | 2 | |

### その他のログオン/ログオフイベント

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4649 | Kerberos再生攻撃が検出された | 0 | |
| 4778 | セッションがウィンドウステーションに再接続された | 0 | Logged at source for RDP or Fast User Switching. |
| 4779 | セッションがウィンドウステーションから切断された | 0 | Logged at source for RDP or Fast User Switching. |
| 4800 | 端末がロックされた | 0 | |
| 4801 | 端末のロックが解除された | 0 | |
| 4802 | スクリーンセーバーが開始された | 0 | |
| 4803 | スクリーンセーバーが停止された | 0 | |
| 5378 | CredSSP Credentials Delegation Blocked | 0 | Usually when WinRM double-hop session was not properly set. |
| 5632 | 無線ネットワークへの802.1x認証 | 0 | |
| 5633 | 有線ネットワークへの802.1x認証 | 0 | |

### 特殊なログオン

"Special groups" and "Special Privileges" can be thought of as Administrator groups or privileges.

ボリューム: Low on client. Medium on DC or network servers.

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4672 | 管理者ログオン | 0 | |
| 4964 | 管理者グループからのログオン | 0 | |

## オブジェクトアクセス

### 証明書サービス

**Note: Enable only for servers providing AD CS role services.**

ボリューム: 低〜中

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗` for AD CS role servers.

Sigmaルールの例:
* `ADCS Certificate Template Configuration Vulnerability with Risky EKU`
* `ADCS Certificate Template Configuration Vulnerability`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4898 | Certificate Services Loaded A Template | 2 | |

**Note: Many イベントIDs are enabled. Only the one with sigma rules is shown above.**

### 詳細なファイル共有

ボリューム: Very high for file servers and DCs, however, may be necessary if you want to track who is accessing what files as well as detect various lateral movement.

デフォルトの設定: `監査なし`

推奨設定: `監査なし` due to the high noise level. Enable if you can though.

Sigmaルールの例:
* `Remote Task Creation via ATSVC Named Pipe`
* `Persistence and Execution at Scale via GPO Scheduled Task`
* `Impacket PsExec Execution`
* `Possible Impacket SecretDump Remote Activity`
* `First Time Seen Remote Named Pipe`
* `Possible PetitPotam Coerce Authentication Attempt`
* `Suspicious Access to Sensitive File Extensions`
* `Transferring Files with Credential Data via Network Shares`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5145 | Network Share File Access | 17 | There are no SACLs (System Access Control Lists) for shared folders so everything is logged. |

### ファイル共有

ボリューム: High for file servers and DCs.

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(5140) Access to ADMIN$ Share`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5140 | ネットワーク共有への接続 | 1 | Can be combined with File System auditing to track what files were accessed. |
| 5142 | ネットワーク共有が作成された | 0 | |
| 5143 | ネットワーク共有が変更された | 0 | |
| 5144 | ネットワーク共有が削除された | 0 | |
| 5168 | SPN Check For SMB/SMB2 Failed | 0 | |

### ファイルシステム

You need to seperately configure audit permissions on files and/or folders in order for access to be logged. 
For example, by right-clicking, opening Properties, Security tab, Advanced, Auditing tab and then adding a Principal and what permissions to monitor.
It is recommended only to monitor access to sensitive files as there will be too much noise if too many files are enabled for logging.

ボリューム: SACL設定による

デフォルトの設定: `監査なし`

推奨設定: Enable SACLs for sensitive files.

Sigmaルールの例:
* `(4663) ISO Image Mount`
* `(4663) Suspicious Teams Application Related ObjectAcess Event`: Detects access to MS Teams authentication tokens.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトハンドルへのリクエスト | 0 | Could fail if the process does not have the right permissions. |
| 4658 | Object Handle Closed | 0 | |
| 4660 | Object Deleted | 0 | |
| 4663 | Access To An Object | 2 | Differs from 4656 in that there are only success events. |
| 4664 | Attempt To Create Hard Link | 0 | |
| 4670 | Object Permission Changed | 0 | |
| 4985 | State Of A Transaction Changed | 0 | Used for Transaction Manager and not relevent for security. |
| 5051 | A File Was Virtualized | 0 | Rarely occurs during LUAFV virtualization. Not relevent for security. |

**Note: EID 4656, 4658, 4660, 4663, 4670 are also used for access to registry and kernel objects as well as removable storage access but need to be configured seperately.** 

### フィルタリングプラットフォームの接続

Logs when WFP (Windows Filtering Platform) allows or blocks port bindings and network connections.

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗` if you have enough space and are not monitoring network connections with sysmon. This should cause a high amount of events though.

Sigmaルールの例:
* `(5156) Enumeration via the Global Catalog`: To detect Bloodhound and similar tools.
* `(5156) RDP over Reverse SSH Tunnel WFP`
* `(5156) Remote PowerShell Sessions Network Connections (WinRM)`
* `(5156) Suspicious Outbound Kerberos Connection`: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5031 | WFP Blocked Incoming Connection | 0 |  |
| 5150 | WFP Blocked A Packet | 0 | |
| 5151 | More Restrictive WFP Filter Blocked A Packet | 0 | |
| 5154 | Process Listening For Connections | 0 | |
| 5155 | Process Blocked To Listen For Connections  | 0 | |
| 5156 | ネットワーク接続 | 4 | |
| 5157 | ネットワーク接続がブロックされた | 0 | |
| 5158 | Process Binded To Port | 0 | |
| 5159 | Process Blocked To Bind To Port | 0 | |

### フィルタリングプラットフォームパケットの破棄

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗` if you have enough space and are not monitoring network connections with sysmon. This should cause a high amount of events though.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5152 | WFP Blocked A Packet | 0 |  |
| 5153 | More Restrictive WFP Filter Blocked A Packet | 0 |  |

### カーネルオブジェクト

Only kernel objects with a matching SACL generate security audit events. You can enable auditing of all kernel objects at `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Audit: Audit the access of global system objects`, however, it is not recommended as you will probably generate too many unneeded events. It is recommended to only enable logging for events that you have detection rules for.

ボリューム: High if auditing access of global system objects is enabled.

デフォルトの設定: `監査なし`

推奨設定: ACSC recommends `成功と失敗`, however, I have encountered a high amount of `4663: Object Access` events when enabling this.

Sigmaルールの例:
* `(4656) Generic Password Dumper Activity on LSASS`
* `(4663) Suspicious Multiple File Rename Or Delete Occurred`: Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may indicate ransomware activity).

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトハンドルへのリクエスト | 4 |  |
| 4658 | Object Handle Closed | 0 |  |
| 4660 | Object Deleted | 0 |  |
| 4663 | Object Access  | 2 |  |

**Note: EID 4656, 4658, 4660, 4663 are also used for access to registry and file system objects as well as removable storage access but need to be configured seperately.** 

### その他のオブジェクトアクセスイベント

It is important to enable as malware will often abuse tasks for persistence and lateral movement.

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4698) Rare Schtasks Creations`: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code.
* `(4699) Scheduled Task Deletion`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4691 | Indirect Access To Object | 0 |  |
| 4698 | Task Created | 2 | |
| 4699 | Task Deleted | 1 | |
| 4700 | Task Enabled | 0 | |
| 4701 | Task Disabled | 1 | |
| 4702 | Task Updated | 0 | |
| 5148 | WFP Detected DoS Attack And Is Blocking Source Packets | 0 |  |
| 5149 | DoS Attack Has Subsided And Normal Processing Resumed | 0 |  |
| 5888 | COM+ Catalog Object Modified | 0 |  |
| 5889 | COM+ Catalog Object Deleted | 0 |  |
| 5890 | COM+ Catalog Object Added | 0 |  |

### レジストリ

Many attacks and malware use the registry so it is a great place for evidence, however, it is difficult to only log only what is needed for detection and if you enable all registry access globally, there will be extreme volume of events and possible performance degredation.

ボリューム: SACLの設定による

デフォルトの設定: `監査なし`

推奨設定: Set SACLs for only the registry keys that you want to monitor.

Sigmaルールの例:
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

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトハンドルへのリクエスト | 2 |  |
| 4657 | Registry Value Modified | 182 |  |
| 4658 | Object Handle Closed | 0 |  |
| 4660 | オブジェクト削除  | 0 |  |
| 4663 | オブジェクトがアクセスされた | 0 |  |
| 4670 | オブジェクトの権限が変更された | 0 |  |

**Note: EID 4656, 4658, 4660, 4663, 4670 are also used for access to kernel and file system objects as well as removable storage access but need to be configured seperately.** 

### リムーバブル記憶域

This logs all file access to removable storage regardless of SACL settings.
You may want to enable to track employees exfiltrating data via USB storage.

ボリューム: Depends on how much removable storage is used.

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗` if you want to monitor external device usage.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトハンドルへのリクエスト | 0 |  |
| 4658 | Object Handle Closed | 0 |  |
| 4663 | Object Access | 0 |  |

**Note: EID 4656, 4658, 4663 are also used for access to registry, kernel and file system objects but need to be configured seperately.** 

### SAM

This will log attempts to access Security Account Manager (SAM) objects, such as user and computer accounts, groups, security descriptors, etc...

ボリューム: High volume of events on Domain Controllers.

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗` if you can but may cause too high volume of noise so should be tested beforehand.

Sigmaルールの例:
* `(4661) Reconnaissance Activity`: Detects activity such as "net user administrator /domain" and "net group domain admins /domain".
* `(4661) AD Privileged Users or Groups Reconnaissance`: Detect privileged users or groups recon based on 4661 eventid and known privileged users or groups SIDs.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4661 | オブジェクトハンドルへのリクエスト | 2 |  |

## ポリシーの変更

### 監査ポリシーの変更

Changes to audit policy that are audited include:
* Changing permissions and audit settings on the audit policy object (by using “auditpol /set /sd” command).
* Changing the system audit policy.
* Registering and unregistering security event sources.
* Changing per-user audit settings.
* Changing the value of CrashOnAuditFail.
* Changing audit settings on an object (for example, modifying the system access control list (SACL) for a file or registry key).
* Changing anything in the Special Groups list.

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4719) Disabling Windows Event Auditing`: Detects anti-forensics via local GPO policy.
 
| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4715 | The audit policy (SACL) on an object was changed. | 0 | Logged regardless of Audit Policy Change settings. |
| 4719 | System audit policy was changed. | 1 | Logged regardless of Audit Policy Change settings. |
| 4817 | Auditing settings on object were changed. | 0 | Logged regardless of Audit Policy Change settings. |
| 4902 | The Per-user audit policy table was created. | 0 | |
| 4904 | An attempt was made to register a security event source. | 0 | |
| 4905 | An attempt was made to unregister a security event source. | 0 | |
| 4906 | The CrashOnAuditFail value has changed. | 0 | Logged regardless of Audit Policy Change settings. |
| 4907 | Auditing settings on object were changed. | 0 | |
| 4908 | Special Groups Logon table modified. | 0 | Logged regardless of Audit Policy Change settings. |
| 4912 | Per User Audit Policy was changed. | 0 | Logged regardless of Audit Policy Change settings. |

### 認証ポリシーの変更

Changes made to authentication policy include:
* Creation, modification, and removal of forest and domain trusts.
* Changes to Kerberos policy under `Computer Configuration > Windows Settings > Security Settings > Account Policies > Kerberos Policy`.
* When any of the following user logon rights is granted to a user or group:
* Access this computer from the network
* Allow logon locally
* Allow logon through Remote Desktop
* Logon as a batch job
* Logon as a service
* Namespace collision, such as when an added trust collides with an existing namespace name.

This setting is useful for tracking changes in domain-level and forest-level trust and privileges that are granted to user accounts or groups.

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4706) Addition of Domain Trusts`: Addition of domains is seldom and should be verified for legitimacy.
 
| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4670 | Permissions on an object were changed. | 0 | |
| 4706 | A new trust was created to a domain. | 1 | |
| 4707 | A trust to a domain was removed. | 0 | |
| 4713 | Kerberos policy was changed. | 0 | |
| 4716 | Trusted domain information was modified. | 0 | |
| 4717 | System security access was granted to an account. | 0 | |
| 4718 | System security access was removed from an account. | 0 | |
| 4739 | Domain Policy was changed. | 0 | |
| 4864 | A namespace collision was detected. | 0 | |
| 4865 | A trusted forest information entry was added. | 0 | |
| 4866 | A trusted forest information entry was removed. | 0 | |
| 4867 | A trusted forest information entry was modified. | 0 | |

### 承認ポリシーの変更

Audits assignment and removal of user rights in user right policies, changes in security token object permission, resource attributes changes and Central Access Policy changes for file system objects.

You can get information related to changes in user rights policies, or changes of resource attributes or Central Access Policy applied to file system objects.
However, if you are using an application or system service that makes changes to system privileges through the AdjustPrivilegesToken API, it is not recommended to enable due to the high volume of events.

ボリューム: 中〜高

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4703 | A user right was adjusted. | 0 | As of Windows 10, this event is generated by applications and services that dynamically adjust token privileges. An example is Microsoft Endpoint Configuration Manager, which makes WMI queries at recurring intervals generating a large amount of events from the svchost.exe process. |
| 4704 | A user right was assigned. | 0 | |
| 4705 | A user right was removed. | 0 | |
| 4670 | Permissions on an object were changed. | 0 | |
| 4911 | Resource attributes of the object were changed. | 0 | |
| 4913 | Central Access Policy on the object was changed. | 0 | |

### フィルタリングプラットフォームポリシーの変更

Audit events generated by changes to the Windows Filtering Platform (WFP), such as the following:
* IPsec services status.
* Changes to IPsec policy settings.
* Changes to Windows Filtering Platform Base Filtering Engine policy settings.
* Changes to WFP providers and engine.

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

There are too many events that are enabled with this sub-category to list up and no sigma detection rules that use these イベントIDs at the moment.

### MPSSVCルールレベルポリシーの変更

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

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4944 | Active policy when FW started. | 0 | |
| 4945 | Rule listed when FW started. | 0 | |
| 4946 | Rule added to FW exception list. | 0 | |
| 4947 | Rule modified to FW exception list. | 0 | |
| 4948 | Rule deleted from FW exception list. | 0 | |
| 4949 | FW settings restored to default. | 0 | |
| 4950 | FW setting changed. | 0 | |
| 4951 | FW rule ignored because major version number was not recognized. | 0 | |
| 4952 | Parts of FW rule ignored because minor version number was not recognized. | 0 | |
| 4953 | FW rule could not be parsed. | 0 | |
| 4954 | FW Group Policy settings changed. New settings applied. | 0 | |
| 4956 | FW active profile changed. | 0 | |
| 4957 | FW did not apply rule. | 0 | |
| 4958 | FW did not apply rule because rule referred to items not configured on this computer. | 0 | |

There are no sigma detection rules for this sub-category at the moment.

### その他のポリシー変更イベント

Audit Other Policy Change Events contains events about EFS Data Recovery Agent policy changes, changes in Windows Filtering Platform filter, status on Security policy settings updates for local Group Policy settings, Central Access Policy changes, and detailed troubleshooting events for Cryptographic Next Generation (CNG) operations.

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: ACSC recommends `成功と失敗`, however, this results in a lot of noise of `5447 (A Windows Filtering Platform filter has been changed)` events being generated.

There are too many events that are enabled with this sub-category to list up and no sigma detection rules that use these イベントIDs at the moment.

## 特権の使用

### 重要でない特権の使用

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

ボリューム: とても高い

デフォルトの設定: `監査なし`

推奨設定: `監査なし`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4673 | A privileged service was called. | 0 | |
| 4674 | An operation was attempted on a privileged object. | 0 | |
| 4985 | The state of a transaction has changed. | 0 | |

**Note: Non-sensitive and sensitive privilege use events use the same イベントID.**

### 重要な特権の使用

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

The use of two privileges, “Back up files and directories” and “Restore files and directories,” generate events only if the `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Audit: Audit the access of global system objects` Group Policy setting is enabled on the computer or device. However, it is not recommended to enable this Group Policy setting because of the high number of events recorded.

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗. However, this may be too noisy.`

Sigmaルールの例:
* `(4673) User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'`: The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.
* `(4673) Suspicious Driver Loaded By User`: Detects the loading of drivers via 'SeLoadDriverPrivilege' required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers. This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.
* `(4674) SCM Database Privileged Operation`: Detects non-system users performing privileged operation os the SCM database.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4673 | A privileged service was called. | 2 | |
| 4674 | An operation was attempted on a privileged object. | 1 | |
| 4985 | The state of a transaction has changed. | 0 | |

**Note: Non-sensitive and sensitive privilege use events use the same イベントID.**

## システム

### その他のシステムイベント

Audit Other System Events contains Windows Firewall Service and Windows Firewall driver start and stop events, failure events for these services and Windows Firewall Service policy processing failures:
* Startup and shutdown of the Windows Firewall service and driver.
* Security policy processing by the Windows Firewall service.
* Cryptography key file and migration operations.
* BranchCache events.

ボリューム: 低

デフォルトの設定: `成功と失敗`

推奨設定: `不明。テストが必要。`

There are too many events that are enabled with this sub-category to list up and no sigma detection rules that use these イベントIDs at the moment.

### セキュリティ状態の変更

Audit Security State Change contains Windows startup, recovery, and shutdown events, and information about changes in system time.

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4616) Unauthorized System Time Modification`: Detect scenarios where a potentially unauthorized application or user is modifying the system time.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4608 | Windows is starting up. | 0 | |
| 4616 | The system time was changed. | 1 | |
| 4621 | Administrator recovered system from CrashOnAuditFail. | 0 | |

### セキュリティシステムの拡張

This policy setting allows you to audit events related to security system extensions or services such as the following:
* A security system extension, such as an authentication, notification, or security package is loaded and is registered with the Local Security Authority (LSA). It is used to authenticate logon attempts, submit logon requests, and any account or password changes. Examples of security system extensions are Kerberos and NTLM.
* A service is installed and registered with the Service Control Manager. The audit log contains information about the service name, binary, type, start type, and service account.

ボリューム: Low, but more on DCs.

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4611) Register new Logon Process by Rubeus`: Detects potential use of Rubeus via registered new trusted logon process.
* `(4697) Invoke-Obfuscation Obfuscated IEX Invocation`
* `(4697) Invoke-Obfuscation Via Use Rundll32`
* `(4697) Invoke-Obfuscation Via Use MSHTA`
* `(4697) CobaltStrike Service Installations`
* `(4697) Credential Dumping Tools Service Execution`
* `(4697) Malicious Service Installations`
* `(4697) Meterpreter or Cobalt Strike Getsystem Service Installation`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4610 | An authentication package has been loaded by the Local Security Authority. | 0 | Should be monitored with an allowlist. |
| 4611 | A trusted logon process has been registered with the Local Security Authority. | 1 | Should display "SYSTEM" in the "Subject" field. |
| 4614 | A notification package has been loaded by the Security Account Manager. | 0 | |
| 4622 | A security package has been loaded by the Local Security Authority. | 0 | |
| 4697 | A service was installed in the system. | 20 | This is the most important event in this sub-category. |

### システムの整合性

Audit System Integrity determines whether the operating system audits events that violate the integrity of the security subsystem:
* Audited events are lost due to a failure of the auditing system.
* A process uses an invalid local procedure call (LPC) port in an attempt to impersonate a client, reply to a client address space, read to a client address space, or write from a client address space.
* A remote procedure call (RPC) integrity violation is detected.
* A code integrity violation with an invalid hash value of an executable file is detected.
* Cryptographic tasks are performed.

According to Microsoft, violations of security subsystem integrity are critical and could indicate a potential security attack.

ボリューム: 低

デフォルトの設定: `成功と失敗`

推奨設定: `成功と失敗`

Currently, there are no sigma rules for this sub-category.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4612 | Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits. | 0 | This is important to monitor. |
| 4615 | Invalid use of LPC port. | 0 |  |
| 4618 | A monitored security event pattern has occurred. | 0 | This event can only be invoked manually. |
| 4816 | RPC detected an integrity violation while decrypting an incoming message. | 0 |  |
| 5038 | Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error. | 0 |  |
| 5056 | A cryptographic self-test was performed. | 0 |  |
| 5057 | A cryptographic primitive operation failed. | 0 |  |
| 5060 | Verification operation failed. | 0 |  |
| 5061 | Cryptographic operation. | 0 |  |
| 5062 | A kernel-mode cryptographic self-test was performed. | 0 |  |
| 6281 | Code Integrity determined that the page hashes of an image file are not valid. The file could be improperly signed without page hashes or corrupt due to unauthorized modification. The invalid hashes could indicate a potential disk device error. | 0 |  |
| 6410 | Code integrity determined that a file does not meet the security requirements to load into a process. | 0 |  |

## グローバルオブジェクトアクセス

You can configure all `ファイルシステム` and `レジストリ` access to be recorded here but it is not recommended due to the very high amount of logs you will generate.