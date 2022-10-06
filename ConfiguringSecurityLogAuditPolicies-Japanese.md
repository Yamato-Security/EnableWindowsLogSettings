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

* 組織レベルでは、グループポリシーまたはInTuneを使用して、Securityログの監査ポリシーを設定することができます。スタンドアロン端末の場合は、ローカルセキュリティポリシーエディタ（`gpedit.msc`）で設定できます。また、PowerShellスクリプトや`auditpol`などのビルトインコマンドを組み込んだBatchクリプトを使用して、スタンドアロン端末およびスタートアップスクリプトで組織レベルの端末を設定することもできます。
* Securityログ監査は、大まかなカテゴリレベルではなく、より細かい設定ができるサブカテゴリレベル（グループポリシーの`コンピュータの構成 > Windowsの設定 > セキュリティの設定 > セキュリティ監査ポリシーの詳細設定 > システム監査ポリシー`）で有効にすべきです。カテゴリレベルで設定してしまうと、多くの不要のイベントが記録され、サブカテゴリレベルで行った詳細な設定が上書きされるリスクがあります。
* このドキュメントでは、そもそも実際に記録されていないイベントIDや監視・DFIR調査に役に立たないサブカテゴリとイベントIDについては記載していません。有効化すべきもののみ記載しています。
* 特定のイベントIDの有効化・無効化はできず、最も細かい設定レベルはサブカテゴリになります。たまにいくつかのノイズが多いイベントIDが記録されますが、サブカテゴリ全体を無効にしない限り、無効にできないのが残念です。
* Sigmaルールの数は、2022/09/24で取得しました。あるイベントについてSigmaルールがほとんどない、あるいはないとしても、そのイベントが重要でないことを意味するわけではないことに注意して下さい。

# SecurityイベントログのカテゴリとイベントID

## アカウントログオン

### 資格情報の確認

ボリューム: NTLMの使用による。ドメインコントローラでは高。

デフォルトの設定: `クライアントOS: 監査なし` | `サーバOS: 成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `Metasploit SMB Authentication`: Detect when someone is running Metasploit on your network.
* `Valid Users Failing to Authenticate from Single Source Using NTLM`: パスワード推測攻撃
* `Invalid Users Failing To Authenticate From Single Source Using NTLM`: ユーザ名の推測
* `Failed Logins with Different Accounts from Single Source System`: パスワードスプレー攻撃

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4776 | ローカルユーザアカウントのNTLM認証 | 5 | 元のイベントメッセージにはDCのみと書かれているが、このイベントはクライアントOSのローカル認証でもログに記録される。 | 

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
| 4773 | Kerberosサービスチケット要求が失敗した | 0 | 実際は使われていない。代わりに4769が使われている。 |

## アカウントの管理

### コンピュータアカウントの管理

ボリューム: ドメインコントローラでは低い

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
| 4765 | SID履歴がアカウントに追加された | 0 | |
| 4766 | アカウントにSID履歴を追加する試みは失敗した | 0 | |
| 4767 | ユーザアカウントのロックが解除された | 0 | |
| 4780 | 管理者グループのメンバーであるアカウントにACLが設定された | 0 | |
| 4781 | アカウントの名前が変更された | 1 | |
| 4794 | DSRM Administrator Password Set | 1 | |
| 4798 | ユーザーローカルグループメンバーシップが列挙された | 0 | |
| 5376 | 資格情報マネージャの資格情報がバックアップされた | 0 | |
| 5377 | 資格情報マネージャの資格情報がバックアップから復元された | 0 | |

## 詳細追跡

### PNPアクティビティ

物理的な攻撃（Rubber Ducky攻撃など）や、誰かがUSBデバイスを介してデータを流出させたことを追跡したい場合に重要です。

ボリューム: 通常、低い

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(6416) External Disk Drive Or USB Storage Device`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 6416 | 新規外部デバイスが認識された | 1 | |
| 6419 | デバイスを無効にする要求 | 0 | |
| 6420 | デバイスが無効にされた | 0 | |
| 6421 | デバイスを有効にする要求 | 0 | |
| 6422 | デバイスが有効にされた | 0 | |
| 6423 | デバイスのインストールが拒否された | 0 | |
| 6424 | 以前拒否されたデバイスのインストールが許可された | 0 | |

### プロセス作成

注意: 非常に重要なコマンドライン情報のログを取るには、別の設定を有効にする必要があります。グループポリシーでは: `コンピュータの構成 > Windowsの設定 > 管理用テンプレート > システム > プロセス作成の監査 > プロセス作成イベントにコマンドラインを含める`

Sigmaルールの約半分は、コマンドラインオプションを有効にしたプロセス作成に依存しているので、Sysmonをインストールし、プロセス作成を監視するように設定していない場合は、Securityログでプロセス作成イベントを有効にした方が良いです。

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: Sysmonがインストールされていない場合は`成功と失敗`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4688 | プロセス作成 | 902 | |
| 4696 | プライマリトークンがプロセスに割り当てされた | 0 | |

### プロセス終了

ファイル容量を節約するために、無効にしておくと良いでしょう。

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: プロセスのライフスパンを追跡したいのでなければ`監査なし`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4689 | プロセス終了 | 1 | |

### RPCイベント

ボリューム: RPCサーバでは高い

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5712 | RPCの試行 | 0 | RPC要求の受信が行われたときに記録される。 |

### トークン権限の調整

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4703 | ユーザ権利の調整 | 0 | |

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
| 4661 | オブジェクトハンドル要求 | 2 | |
| 4662 | オブジェクトに対する操作 | 6 | |

### ディレクトリサービスの変更

ボリューム: ドメインコントローラでは高。

デフォルトの設定: `監査なし`

推奨設定: `クライアントOS: 監査なし` | `ADDS Server: 成功と失敗`

Sigmaルールの例:
* `Powerview Add-DomainObjectAcl DCSync AD Extend Right`: Backdooring domain object to grant the rights associated with DCSync to a regular user or machine account.
* `Active Directory User Backdoors`: Detects scenarios where one can control another users or computers account without having to use their credentials.
* `Possible DC Shadow`
* `Suspicious LDAP-Attributes Used`: Detects LDAPFragger, a C2 tool that lets attackers route Cobalt Strike beacon data over LDAP attributes.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5136 | ディレクトリサービスオブジェクトの変更 | 6 | |
| 5137 | ディレクトリサービスオブジェクトの作成 | 0 | |
| 5138 | ディレクトリサービスオブジェクトの復元 | 0 | |
| 5139 | ディレクトリサービスオブジェクトの移動 | 0 | |
| 5141 | ディレクトリサービスオブジェクトの削除 | 0 | |

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
| 4625 | ロックアウトによるログオンに失敗 | 4 | |

### グループメンバーシップ

ボリューム: ログオンがある度に、ユーザのグループメンバーシップについてのログが記録される。

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

ボリューム: クライアントOSでは低。ドメインコントローラやネットワークサーバでは中。

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
| 4778 | セッションがウィンドウステーションに再接続された | 0 | RDPもしくはユーザーの簡易切り替えのログが送信元の端末に記録される。 |
| 4779 | セッションがウィンドウステーションから切断された | 0 | RDPもしくはユーザーの簡易切り替えのログが送信元の端末に記録される。 |
| 4800 | 端末がロックされた | 0 | |
| 4801 | 端末のロックが解除された | 0 | |
| 4802 | スクリーンセーバーが開始された | 0 | |
| 4803 | スクリーンセーバーが停止された | 0 | |
| 5378 | 要求された資格情報の委任は、ポリシーによって許可されない | 0 | 通常、WinRMダブルホップセッションのCredSSP委任が正しく設定されていない場合に発生する。 |
| 5632 | 無線ネットワークへの802.1x認証 | 0 | |
| 5633 | 有線ネットワークへの802.1x認証 | 0 | |

### 特殊なログオン

「特別なグループ」と「特別な権限」は管理者グループと管理者権限だと考えたら良いです。

ボリューム: クライアントOSでは低。DCやネットワークサーバでは中。

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

推奨設定: ADCSロールのサーバでは`成功と失敗`

Sigmaルールの例:
* `ADCS Certificate Template Configuration Vulnerability with Risky EKU`
* `ADCS Certificate Template Configuration Vulnerability`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4898 | 証明書サービスがテンプレートをロードした | 2 | |

**注意: 多くのイベントIDが有効になります。SigmaルールがあるイベントIDだけ上記で記載されています。**

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
| 5145 | ネットワーク共有へのファイルアクセス | 17 | There are no SACLs (System Access Control Lists) for shared folders so everything is logged. |

### ファイル共有

ボリューム: ファイルサーバやドメインコントローラでは高。

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
| 5168 | SMB/SMB2のSPNチェックに失敗 | 0 | |

### ファイルシステム

You need to seperately configure audit permissions on files and/or folders in order for access to be logged. 
For example, by right-clicking, opening Properties, Security tab, Advanced, Auditing tab and then adding a Principal and what permissions to monitor.
It is recommended only to monitor access to sensitive files as there will be too much noise if too many files are enabled for logging.

ボリューム: SACL設定による

デフォルトの設定: `監査なし`

推奨設定: センシティブなファイルにSACLを設定すること

Sigmaルールの例:
* `(4663) ISO Image Mount`
* `(4663) Suspicious Teams Application Related ObjectAcess Event`: Detects access to MS Teams authentication tokens.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトハンドル要求 | 0 | Could fail if the process does not have the right permissions. |
| 4658 | オブジェクトハンドルが閉じられた | 0 | |
| 4660 | オブジェクト削除 | 0 | |
| 4663 | オブジェクトアクセス | 2 |　4656と異なって、成功イベントしか記録されない。 |
| 4664 | ハードリンク作成の試行 | 0 | |
| 4670 | オブジェクト権限の変更 | 0 | |
| 4985 | トランザクション状態の変更 | 0 | Used for Transaction Manager and not relevent for security. |
| 5051 | ファイルが仮想化された | 0 | Rarely occurs during LUAFV virtualization. Not relevent for security. |

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
| 5031 | WFPが受信接続を遮断した | 0 |  |
| 5150 | WFPがパケットを遮断した | 0 | |
| 5151 | より限定的なWFPフィルターがパケットを遮断した | 0 | |
| 5154 | プロセスが通信を待ち受けている | 0 | |
| 5155 | プロセスの通信待受が拒否された  | 0 | |
| 5156 | ネットワーク接続 | 4 | |
| 5157 | ネットワーク接続がブロックされた | 0 | |
| 5158 | プロセスがポートにバインドした | 0 | |
| 5159 | プロセスのポートバインドが拒否された | 0 | |

### フィルタリングプラットフォームパケットの破棄

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗` if you have enough space and are not monitoring network connections with sysmon. This should cause a high amount of events though.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 5152 | WFPがパケットを遮断した | 0 |  |
| 5153 | より限定的なWFPフィルターがパケットを遮断した | 0 |  |

### カーネルオブジェクト

Only kernel objects with a matching SACL generate security audit events. You can enable auditing of all kernel objects at `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Audit: Audit the access of global system objects`, however, it is not recommended as you will probably generate too many unneeded events. It is recommended to only enable logging for events that you have detection rules for.

ボリューム: High if auditing access of global system objects is enabled.

デフォルトの設定: `監査なし`

推奨設定: ACSC recommends `成功と失敗`, however, I have encountered a high amount of `4663: オブジェクトアクセス` events when enabling this.

Sigmaルールの例:
* `(4656) Generic Password Dumper Activity on LSASS`
* `(4663) Suspicious Multiple File Rename Or Delete Occurred`: Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may indicate ransomware activity).

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトハンドル要求 | 4 |  |
| 4658 | オブジェクトハンドルが閉じられた | 0 |  |
| 4660 | オブジェクト削除 | 0 |  |
| 4663 | オブジェクトアクセス  | 2 |  |

**Note: EID 4656, 4658, 4660, 4663 are also used for access to registry and file system objects as well as removable storage access but need to be configured seperately.** 

### その他のオブジェクトアクセスイベント

マルウェアは、しばしば永続性と横展開のためにタスクを悪用するので、有効にすることが重要です。

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4698) Rare Schtasks Creations`: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code.
* `(4699) Scheduled Task Deletion`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4691 | Indirect Access To Object | 0 |  |
| 4698 | タスク作成 | 2 | |
| 4699 | タスク削除 | 1 | |
| 4700 | タスクの有効化 | 0 | |
| 4701 | タスクの無効化 | 1 | |
| 4702 | タスク更新 | 0 | |
| 5148 | WFPがDoS攻撃を検知し、ソースパケットを遮断している | 0 |  |
| 5149 | DoS攻撃は沈静化し、通常の処理が再開された | 0 |  |
| 5888 | COM+カタログオブジェクト変更 | 0 |  |
| 5889 | COM+カタログオブジェクト削除 | 0 |  |
| 5890 | COM+カタログオブジェクト作成 | 0 |  |

### レジストリ

Many attacks and malware use the registry so it is a great place for evidence, however, it is difficult to only log only what is needed for detection and if you enable all registry access globally, there will be extreme volume of events and possible performance degredation.

ボリューム: SACLの設定による

デフォルトの設定: `監査なし`

推奨設定: 監視したいレジストリキーのみSACLを設定すること

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
| 4656 | オブジェクトハンドル要求 | 2 |  |
| 4657 | レジストリ値の変更 | 182 |  |
| 4658 | オブジェクトハンドルが閉じられた | 0 |  |
| 4660 | オブジェクト削除  | 0 |  |
| 4663 | オブジェクトアクセス | 0 |  |
| 4670 | オブジェクト権限の変更 | 0 |  |

**Note: EID 4656, 4658, 4660, 4663, 4670 are also used for access to kernel and file system objects as well as removable storage access but need to be configured seperately.** 

### リムーバブル記憶域

SACLの設定に関係なく、リムーバブルストレージへのすべてのファイルアクセスがログに記録されます。
USBストレージ経由でデータを流出させる従業員などを追跡したい場合は有効にすると良いでしょう。

ボリューム: リムーバブルストレージの使用量に依存する。

デフォルトの設定: `監査なし`

推奨設定: 外付けデバイスの使用を監視したい場合は`成功と失敗`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4656 | オブジェクトハンドル要求 | 0 |  |
| 4658 | オブジェクトハンドルが閉じられた | 0 |  |
| 4663 | オブジェクトアクセス | 0 |  |

**Note: EID 4656, 4658, 4663 are also used for access to registry, kernel and file system objects but need to be configured seperately.** 

### SAM

これは、ユーザおよびコンピュータアカウント、グループ、セキュリティ記述子などのSecurity Account Manager（SAMオブジェクトにアクセスしようとする試みを記録します。

ボリューム: ドメインコントローラでは高。

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗` if you can but may cause too high volume of noise so should be tested beforehand.

Sigmaルールの例:
* `(4661) Reconnaissance Activity`: Detects activity such as "net user administrator /domain" and "net group domain admins /domain".
* `(4661) AD Privileged Users or Groups Reconnaissance`: Detect privileged users or groups recon based on 4661 eventid and known privileged users or groups SIDs.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4661 | オブジェクトハンドル要求 | 2 |  |

## ポリシーの変更

### 監査ポリシーの変更

監査される監査ポリシーの変更には、次のものが含まれる:
* 監査ポリシーオブジェクトのアクセス許可と監査設定の変更 (`auditpol /set /sd`コマンドの使用)
* システム監査ポリシーの変更
* セキュリティイベントソースの登録と登録解除
* ユーザごとの監査設定の変更
* CrashOnAuditFail値の変更
* オブジェクトの監査設定の変更 (例: ファイルまたはレジストリキーのシステムアクセス制御リスト(SACL)の変更)
* 特別なグループリスト内の変更

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4719) Disabling Windows Event Auditing`: Detects anti-forensics via local GPO policy.
 
| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4715 | オブジェクトの監査ポリシー(SACL)が変更された | 0 | 監査ポリシーの変更の設定に関係なくログが記録される。 |
| 4719 | システム監査ポリシーが変更された | 1 | 監査ポリシーの変更の設定に関係なくログが記録される。 |
| 4817 | オブジェクトの監査設定が変更された | 0 | 監査ポリシーの変更の設定に関係なくログが記録される。 |
| 4902 | ユーザごとの監査ポリシーテーブルが作成された | 0 | |
| 4904 | セキュリティイベントソースの登録が試行された | 0 | |
| 4905 | セキュリティイベントソース登録の解除が試行された | 0 | |
| 4906 | CrashOnAuditFailの値が変更された | 0 | 監査ポリシーの変更の設定に関係なくログが記録される。 |
| 4907 | オブジェクトの監査設定が変更された | 0 | |
| 4908 | 特別なグループログオンテーブルが変更された | 0 | 監査ポリシーの変更の設定に関係なくログが記録される。 |
| 4912 | ユーザごとの監査ポリシーが変更された | 0 | 監査ポリシーの変更の設定に関係なくログが記録される。 |

### 認証ポリシーの変更

認証ポリシーに加えた変更は次のとおり:
* フォレストとドメインの信頼の作成、変更、および削除。
* `コンピューターの構成 > Windows設定 > アカウントポリシー > Kerberosポリシー`のKerberosポリシー設定に対する変更。
* ユーザーまたはグループに次のユーザー ログオン権限が付与されている場合。
  * ネットワークからこのコンピューターにアクセスする
  * ローカルでのログオンを許可する
  * リモートデスクトップ経由のログオンを許可する
  * バッチジョブとしてのログオン
  * サービスとしてのログオン
* 追加された信頼が既存の名前空間名と衝突する場合など、名前空間の競合。

この設定は、ドメインレベルおよびフォレストレベルの信頼と、ユーザアカウントまたはグループに付与される特権の変化を追跡するのに便利です。

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4706) Addition of Domain Trusts`: Addition of domains is seldom and should be verified for legitimacy.
 
| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4670 | オブジェクト権限の変更  | 0 | |
| 4706 | ドメインに新しい信頼が作成された | 1 | |
| 4707 | ドメインへの信頼が削除された | 0 | |
| 4713 | Kerberosポリシーが変更された | 0 | |
| 4716 | 信頼できるドメイン情報が変更された | 0 | |
| 4717 | システムセキュリティアクセスがアカウントに付与された | 0 | |
| 4718 | システムセキュリティアクセスがアカウントから削除された | 0 | |
| 4739 | ドメイン ポリシーが変更された | 0 | |
| 4864 | 名前空間の競合が検出され | 0 | |
| 4865 | 信頼できるフォレスト情報エントリが追加された | 0 | |
| 4866 | 信頼できるフォレスト情報エントリが削除された | 0 | |
| 4867 | 信頼できるフォレスト情報エントリが変更された | 0 | |

### 承認ポリシーの変更

Audits assignment and removal of user rights in user right policies, changes in security token object permission, resource attributes changes and Central Access Policy changes for file system objects.

You can get information related to changes in user rights policies, or changes of resource attributes or Central Access Policy applied to file system objects.
However, if you are using an application or system service that makes changes to system privileges through the AdjustPrivilegesToken API, it is not recommended to enable due to the high volume of events.

ボリューム: 中〜高

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4703 | ユーザ権利の調整 | 0 | As of Windows 10, this event is generated by applications and services that dynamically adjust token privileges. An example is Microsoft Endpoint Configuration Manager, which makes WMI queries at recurring intervals generating a large amount of events from the svchost.exe process. |
| 4704 | ユーザ権限の割り当て | 0 | |
| 4705 | ユーザ権限の削除 | 0 | |
| 4670 | オブジェクト権限の変更 | 0 | |
| 4911 | オブジェクトのリソース属性が変更された | 0 | |
| 4913 | オブジェクトの中央アクセス ポリシーが変更された | 0 | |

### フィルタリングプラットフォームポリシーの変更

Windows Filtering Platform（WFP）の変更によって発生する以下のようなイベントを監査します:
* IPsecサービスの状態。
* IPsecポリシー設定の変更。
* フィルタープラットフォームベースWindowsポリシー設定に対する変更点。
* WFPプロバイダーとエンジンに対する変更。

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

このサブカテゴリで有効にされるイベントが多すぎて、リストアップできません。また、これらのイベントIDを使用するSigmaルールは、現時ありません。

### MPSSVCルールレベルポリシーの変更

Audit MPSSVC Rule-Level Policy Change determines whether the operating system generates audit events when changes are made to policy rules for the Microsoft Protection Service (MPSSVC.exe).
The Microsoft Protection Service, which is used by Windows Firewall, is an integral part of the computer’s threat protection against malware. The tracked activities include:
* ファイアウォール(`FW`)開始時のポリシー
* FWルールの変更
* FW例外リストの変更
* FW設定の変更
* FWルールの適用と無視
* FWのグループポリシー設定の変更。

FWルールの変更は、端末のセキュリティ状態を把握し、ネットワーク攻撃からどの程度保護されているかを知るために重要です。

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: `不明。テストが必要。`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4944 | FW起動時のポリシー | 0 | |
| 4945 | FW起動時のルール一覧表示 | 0 | |
| 4946 | FW例外リストにルールが追加された | 0 | |
| 4947 | FW例外リストのルールが変更された | 0 | |
| 4948 | FW例外リストのルールが削除された | 0 | |
| 4949 | FWが既定値に復元された | 0 | |
| 4950 | FW設定が変更された | 0 | |
| 4951 | FW rule ignored because major version number was not recognized. | 0 | |
| 4952 | Parts of FW rule ignored because minor version number was not recognized. | 0 | |
| 4953 | FWルールをパースできなかった | 0 | |
| 4954 | GPOによるFWルールの変更　 | 0 | |
| 4956 | FWのアクティブプロファイルが変更された | 0 | |
| 4957 | FWルールが適用されなかった | 0 | |
| 4958 | FW did not apply rule because rule referred to items not configured on this computer. | 0 | |

現在、このサブカテゴリーにはSigmaルールはありません。

### その他のポリシー変更イベント

Audit Other Policy Change Events contains events about EFS Data Recovery Agent policy changes, changes in Windows Filtering Platform filter, status on Security policy settings updates for local Group Policy settings, Central Access Policy changes, and detailed troubleshooting events for Cryptographic Next Generation (CNG) operations.

ボリューム: 低

デフォルトの設定: `監査なし`

推奨設定: ACSC recommends `成功と失敗`, however, this results in a lot of noise of `5447 (A Windows Filtering Platform filter has been changed)` events being generated.

このサブカテゴリで有効にされるイベントが多すぎて、リストアップできません。また、これらのイベントIDを使用するSigmaルールは、現時ありません。

## 特権の使用

### 重要でない特権の使用

以下の`重要でない特権の使用`イベントが記録されます:
* 資格情報マネージャーに信頼された呼び出し側としてアクセス
* ドメインにワークステーションを追加
* プロセスのメモリ クォータの増加
* 走査チェックのバイパス
* システム時刻の変更
* タイムゾーンの変更
* ページファイルの作成
* グローバルオブジェクトの作成
* 永続的共有オブジェクトの作成
* シンボリックリンクの作成
* リモートコンピューターからの強制シャットダウン
* プロセスワーキング セットの増加
* スケジューリング優先順位の繰り上げ
* メモリ内のページのロック
* オブジェクトラベルの変更
* ボリュームの保守タスクを実行
* 単一プロセスのプロファイル
* システムパフォーマンスのプロファイル
* ドッキングステーションからコンピューターを削除
* システムのシャットダウン
* ディレクトリサービスデータの同期化

ボリューム: とても高い

デフォルトの設定: `監査なし`

推奨設定: `監査なし`

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4673 | 特権サービスが呼び出された | 0 | |
| 4674 | 特権オブジェクトに対する操作の試行 | 0 | |
| 4985 | トランザクション状態の変更 | 0 | |

**注意: 重要でない特権の使用イベントと重要な特権の使用イベントは同じイベントIDを使用します。**

### 重要な特権の使用

以下の`重要な特権の使用`イベントが記録されます:
* オペレーティングシステムの一部として機能する
* ファイルとディレクトリのバックアップ
* ファイルとディレクトリの復元
* トークンオブジェクトの作成
* プログラムのデバッグ
* コンピュータとユーザアカウントに委任時の信頼を付与
* セキュリティ監査の生成
* 認証後にクライアントを偽装
* デバイスドライバーのロードとアンロード
* 監査とセキュリティログの管理
* ファームウェア環境値の修正
* プロセスレベルのトークンを置き換える
* ファイルとその他のオブジェクトの所有権の取得
 
The use of two privileges, “Back up files and directories” and “Restore files and directories,” generate events only if the `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Audit: Audit the access of global system objects` Group Policy setting is enabled on the computer or device. However, it is not recommended to enable this Group Policy setting because of the high number of events recorded.

ボリューム: 高

デフォルトの設定: `監査なし`

推奨設定: `成功と失敗`だが、ノイズが多すぎる可能性がある

Sigmaルールの例:
* `(4673) User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'`: The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.
* `(4673) Suspicious Driver Loaded By User`: Detects the loading of drivers via 'SeLoadDriverPrivilege' required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. This user right does not apply to Plug and Play device drivers. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers. This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.
* `(4674) SCM Database Privileged Operation`: Detects non-system users performing privileged operation os the SCM database.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4673 | 特権サービスが呼び出された | 2 | |
| 4674 | 特権オブジェクトに対する操作の試行 | 1 | |
| 4985 | トランザクション状態の変更 | 0 | |

**注意: 重要でない特権の使用イベントと重要な特権の使用イベントは同じイベントIDを使用します。**

## システム

### その他のシステムイベント

その他のシステムイベントの監査には、WindowsファイアウォールサービスとWindowsファイアウォールドライバーの開始および停止イベント、これらのサービスのエラーイベント、およびWindowsファイアウォールサービスポリシー処理エラーが含まれます:
* ファイアウォールサービスの起動とシャットダウン
* ファイアウォールサービスによるポリシーの処理
* 暗号化キーファイルと移行操作
* BranchCacheイベント

ボリューム: 低

デフォルトの設定: `成功と失敗`

推奨設定: `不明。テストが必要。`

このサブカテゴリで有効にされるイベントが多すぎて、リストアップできません。また、これらのイベントIDを使用するSigmaルールは、現時ありません。

### セキュリティ状態の変更

セキュリティ状態の変更には、端末起動、回復、シャットダウンの各イベント、およびシステム時間の変更に関する情報が含まれています。

ボリューム: 低

デフォルトの設定: `成功`

推奨設定: `成功と失敗`

Sigmaルールの例:
* `(4616) Unauthorized System Time Modification`: Detect scenarios where a potentially unauthorized application or user is modifying the system time.

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4608 | 端末起動 | 0 | |
| 4616 | システム時刻の変更 | 1 | |
| 4621 | 管理者がCrashOnAuditFailからシステムを回復した | 0 | |

### セキュリティシステムの拡張

認証パッケージ、通知パッケージ、またはセキュリティパッケージの読み込みに関する情報と、信頼できるログオンプロセス登録イベントに関する情報が含まれます:
* セキュリティ拡張機能コードが読み込まれます (認証、通知、セキュリティ パッケージなど)。セキュリティ拡張機能コードはLSAに登録され、ログオン試行の認証、ログオン要求の送信、アカウントまたはパスワードの変更の通知を受け取る際に使用され、信頼されます。この拡張コードの例は、KerberosやNTLMなどのセキュリティサポートプロバイダーです。
* サービスがインストールされています。サービスがサービスコントロールマネージャーに登録されると、監査ログが生成されます。監査ログには、サービス名、バイナリ、種類、開始の種類、およびサービスアカウントに関する情報が含まれます。

ボリューム: 低。ドメインコントローラでは高？

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
| 4610 | LSAが認証パッケージを読み込んだ | 0 | Should be monitored with an allowlist. |
| 4611 | 信頼できるログオンプロセスがLSAに登録された | 1 | Should display "SYSTEM" in the "Subject" field. |
| 4614 | SAMが通知パッケージを読み込んだ | 0 | |
| 4622 | LSAがセキュリティパッケージを読み込んだ | 0 | |
| 4697 | サービスインストール | 20 | このサブカテゴリでは最も重要なイベント。Win 10/2016以上が必要。 |

### システムの整合性

監査システム整合性は、オペレーティングシステムがセキュリティサブシステムの整合性に違反するイベントを監査するかどうかを決定します:
* 監査システムの障害により、監査イベントが失われた。
* プロセスは、クライアントの偽装、クライアントアドレス空間への返信、クライアントアドレス空間への読み取り、またはクライアントアドレス空間からの書き込みを行う試みで、無効なローカルプロシージャ呼び出し(LPC)ポートを使用した。
* リモートプロシージャ呼び出し(RPC)整合性違反が検出された。
* 実行可能ファイルの無効なハッシュ値を持つコード整合性違反が検出された。
* 暗号化タスクが実行された。

マイクロソフトによると、セキュリティサブシステムの整合性の違反は重大であり、潜在的なセキュリティ攻撃を示している可能性があります。

ボリューム: 低

デフォルトの設定: `成功と失敗`

推奨設定: `成功と失敗`

現在、このサブカテゴリーにはSigmaルールはありません。

| イベントID | タイトル | Sigmaルール数 | 備考欄 |
| :---: | :---: | :---: | :---: |
| 4612 | リソース切れで一部のログが失われた可能性がある | 0 | 監視すべき。 |
| 4615 | LPCポートの使用が無効 | 0 |  |
| 4618 | 監視対象のセキュリティイベントパターンが発生した | 0 | このイベントは手動で呼び出された時だけ記録される。 |
| 4816 | RPCが受信メッセージの復号中に整合性違反が起こった | 0 |  |
| 5038 | イメージのハッシュ値が不正 | 0 | 元のイベントタイトル: `コードの整合性により、ファイルのイメージ ハッシュが無効であると判断されました。 不正な変更が原因でファイルが破損している可能性があります。無効なハッシュは、ディスク デバイス エラーの可能性があることを示している可能性があります。`  |
| 5056 | 暗号化の自己テストの実行 | 0 |  |
| 5057 | 暗号化プリミティブ操作の失敗 | 0 |  |
| 5060 | 検証操作の失敗 | 0 |  |
| 5061 | 暗号化操作 | 0 |  |
| 5062 | カーネルモードの暗号化セルフテストの実行 | 0 |  |
| 6281 | イメージのページハッシュ値が不正 | 0 | 元のイベントタイトル: `コード整合性により、イメージファイルのページハッシュが無効であると判断されました。ページハッシュなしでファイルに正しく署名されていないか、不正な変更が原因で破損している可能性があります。無効なハッシュは、潜在的なディスクデバイスエラーを示している可能性があります。` |
| 6410 | Code integrity determined that a file does not meet the security requirements to load into a process. | 0 | 元のイベントタイトル: `コードの整合性により、ファイルがプロセスに読み込むセキュリティ要件を満たしていないと判断されました。` |

## グローバルオブジェクトアクセス

ここですべての`ファイルシステム`と`レジストリ`アクセスを記録するように設定できますが、非常に多くのログが生成されるため、実運用ではお勧めしません。
検出ルールを作成するために、どのレジストリキーとファイルが変更されたかを調べるために、攻撃のシミュレーションを行う際に有効にすることが推奨されます。