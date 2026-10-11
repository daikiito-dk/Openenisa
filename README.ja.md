# openenisa

[![CI](https://github.com/daikiito-dk/Openenisa/actions/workflows/ci.yml/badge.svg)](https://github.com/daikiito-dk/Openenisa/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)

[English](README.md) | **日本語**

> DevOps のためのオープンソース CSAF 2.0 / ENISA 報告エンジン。

**SBOM・脆弱性フィード・VEX ステートメント**を、**スキーマ検証済みの CSAF 2.0 文書**と**ENISA 提出用の早期警告エンベロープ**に変換します。サイバーレジリエンス規則(CRA)の24時間タイマーに対応。単一の静的バイナリ、完全オフライン、CI パイプラインとインシデント対応の自動化のために設計されています。

## なぜ今必要か

**2026年9月11日**以降、デジタル要素を含む製品を EU 市場に投入するすべての製造者は、アクティブに悪用されている脆弱性を ENISA に報告する義務を負います。

| 段階 | 期限 | 気知からの経過 |
|---|---|---|
| 早期警告 (Early warning) | 24時間 | 第14条(1) |
| インシデント通知 (Notification) | 72時間 | 第14条(2) |
| 最終報告 (Final report) | 14日 (336時間) | 第14条(3) |

監視フィードが「CVE-2023-48795 が悪用中で、あなたのファームウェアに含まれている」と告げた瞬間、**何を・どんな形式で・いつまでに** ENISA に送りますか?今日その答えは、CVE ID を Web ポータルに手で転記しながら時計を焦らす作業です。`openenisa` はコマンド1つで答えます。**SBOM を入力すれば、検証済みの提出可能文書が出力される。**

なお ENISA の Single Reporting Platform は [portal.cra-srp.enisa.europa.eu](https://portal.cra-srp.enisa.europa.eu) で稼働中ですが、公開マシン API はまだありません。そのため `openenisa` は**送信可能なエンベロープを生成し、法定期限を追跡**します。送信手段はプラグ可能な設計です(現在はポータル手動、API 公開後に自動化)。

## 30秒デモ

```console
$ openenisa pipeline \
    --sbom examples/sbom/mx2400-firmware.cyclonedx-1.5.json \
    --feed examples/vulns/osv-feed.jsonl \
    --vex examples/vex/mx2400-openssl.openvex.json \
    --vex examples/vex/mx2400-busybox.csaf-vex.json \
    --out-dir openenisa-out \
    --vendor-name "Meridian Systems" \
    --vendor-namespace "https://meridian.example" \
    --exploited

== 1/4 SBOM ==
  Format      CycloneDX 1.5 (JSON)
  Components  4
  Product     MX-2400 Server Firmware 2.4.1

== 2/4 MATCH ==
3 finding(s) from 4 feed record(s) across 1 feed(s).

== 3/4 VEX TRIAGE ==
2 VEX statement(s) applied (2 matched, 0 unmatched).
  affected -> not_affected (CVE-2024-0727)
  affected -> fixed (CVE-2023-42366)

== 4/4 DOCUMENTS ==
ENISA early-warning envelope: due 2026-10-11T09:00:00Z [ON TRACK] (envelope valid: true)
```

4段階のストーリー: SBOM は4コンポーネントを識別し、OSV フィードは3件の CVE にマッチし、VEX ステートメントがうち2件を抑制し(このビルドの openssl は CVE-2024-0727 の影響を受けない、busybox の CVE-2023-42366 は修正済み)、**残る1件 — libssh2 の Terrapin (CVE-2023-48795) だけが ENISA エンベロープに入る。** 監査証跡も完全に残ります。`openenisa-out/` には以下が出力されます。

- `findings.json` — トリアージ済みの中間 findings(コンポーネント単位の証拠つき)
- `csaf.json` — 組み込み OASIS スキーマに対して検証済みの CSAF 2.0 VEX 文書
- `enisa-early-warning.json` — 期限計算と証拠を組み込んだ ENISA エンベロープ

## インストール

**前提:** Rust 1.85 以上。

```console
$ cargo install --git https://github.com/daikiito-dk/Openenisa openenisa
```

ソースからビルド:

```console
$ git clone https://github.com/daikiito-dk/Openenisa
$ cd Openenisa
$ make install
```

Linux (amd64/arm64)・macOS (arm64)・Windows のビルド済みバイナリは毎回の[リリース](https://github.com/daikiito-dk/Openenisa/releases)に添付されます。

## コマンド

| コマンド | 機能 |
|---|---|
| `parse <sbom>` | 対応 SBOM を正規化。`--json` で機械可読出力 |
| `match --sbom ... --feed ...` | OSV フィードとのマッチング(purl 同一性、SEMVER/ECOSYSTEM レンジ) |
| `triage --findings ... --vex ...` | OpenVEX / CSAF VEX / CycloneDX VEX ステートメントの適用 |
| `csaf --findings ... --vendor-name ... --vendor-namespace ...` | CSAF 2.0 VEX 文書の生成 |
| `validate <file>` | CSAF・findings・エンベロープを組み込みスキーマで検証 |
| `enisa deadlines --aware-at ...` | 24時間 / 72時間 / 14日の法定期限を表示 |
| `enisa report --findings ... --type early-warning ...` | CSAF + 証拠を組み込んだ ENISA エンベロープの生成 |
| `enisa submit <envelope> [--now ...]` | ドライラン: 準備確認 + 時計 + 送信テンプレート |
| `pipeline` | 上記すべてを1コマンドで。CI 用終了コードつき |

終了コード: `0` 正常、`1` エラー、`2` しきい値違反(`--fail-on affected` はトリアージ後も known-affected が残れば失敗。「出荷停止」の CI ゲート)。全コマンドが `--json` 対応。

## 検証は儀式ではない

`validate` は**OASIS 公式 CSAF 2.0 JSON スキーマ**(errata 01、FIRST CVSS 2.0/3.0/3.1 スキーマをインライン束縛)を組み込み、JSON スキーマだけでは表現できない適合性チェックを追加します。

- リリース日付の順序(`initial_release_date` ≤ `current_release_date`)
- `revision_history` とトラッキング `version` の同期
- `product_status` の全 product id が `product_tree` で解決可能
- `purl` 識別ヘルパーの整形
- 全タイムスタンプが RFC 3339
- 文書カテゴリが `csaf_*` 規約に従う

さらに openenisa 自身の形式(findings 中間形式と ENISA エンベロープ)も検証します。完全オフライン。ネットワークなし、電話-homeなし、言い訳なし。

## 再現可能

同じ入力と同じ `--at` タイムスタンプはバイト同一の文書を生成します。トラッキング ID は実時間ではなく証拠の SHA-256 から派生します。インシデント対応は事後に監査され、監査は再現性を要求します。

## 対応形式

| 入力 | 形式 |
|---|---|
| SBOM | CycloneDX 1.4 / 1.5 / 1.6(JSON + XML)、SPDX 2.3(JSON + XML)、SPDX 3.0(JSON-LD) |
| 脆弱性フィード | OSV(JSONL / NDJSON / 配列 / バンドル) |
| VEX | OpenVEX、CSAF VEX、CycloneDX 組み込み VEX |
| 出力 | CSAF 2.0 VEX、ENISA エンベロープ、openenisa findings |

## CI/CD

付属の [GitHub Action](action.yml):

```yaml
- uses: daikiito-dk/Openenisa@main
  with:
    sbom: dist/bom.json
    feeds: |
      advisories/osv-feed.jsonl
    vendor-name: "Meridian Systems"
    vendor-namespace: "https://meridian.example"
    fail-on: affected   # known-affected が残ればワークフローを失敗させる
```

GitLab CI と Jenkins のレシピは [docs/ci-cd.md](docs/ci-cd.md)。

## ディレクトリ構成

```
src/
  model/        正規化 SBOM/finding モデル(purl パース、semver)
  ingest/       CycloneDX + SPDX パーサー(JSON と XML)
  feed/         OSV フィード読み込み + マッチングエンジン
  vex/          OpenVEX / CSAF VEX / CycloneDX VEX 相関器
  csaf/         CSAF 2.0 ビルダー + 組み込みスキーマ検証
  enisa/        CRA 第14条の時計、エンベロープ、準備確認
  cli/          コマンドサーフェス(clap)
schemas/
  csaf/2.0/     OASIS スキーマ(errata 01) + FIRST CVSS スキーマ + オフライン束縛
  openenisa/    openenisa findings 中間スキーマ
  enisa/        ENISA エンベロープスキーマ
examples/       実行可能なコーパス: SBOM 4種、VEX 文書、OSV フィード、期待出力
scripts/        bundle_csaf.py — オフラインスキーマ束縛の再生成
tests/          エンドツーエンド CLI テスト
docs/           仕様、CRA 報告ガイド、CI/CD レシピ
```

## ステータスと正直な限界

- **法的助言ではありません。** openenisa は文書組み立てと期限計算を自動化します。コンプライアンス責任は製造者に残ります。[docs/cra-reporting.md](docs/cra-reporting.md) を参照。
- **「アクティブに悪用されている」は人間の判断です。** `--exploited` はあなたの判断を証拠とともに記録します。悪用検知は行いません。
- **ENISA SRP にはまだ公開 API がありません。** `enisa submit` はオフラインのドライランです。送信テンプレートを表示し、準備状況を追跡します。API が公開されれば送信はプラグインになります。
- **XML サポートは実用的サブセットです。** CycloneDX XML 1.4〜1.6 と SPDX 2.3 XML はストリーミングリーダーでパースします。特殊な構造は完全には正規化されない場合があります。
- **CVE/OSV のダウンロードは内蔵していません。** フィードは自前で用意します(OSV.dev がエコシステム別ダンプを公開)。決定論的でエアギャップ環境に対応します。

## フェーズ2: PassportX Platform

openenisa はオープンコアです。計画中の **PassportX Platform** は、継続的フリート監視・マルチプロダクトダッシュボード・デジタルプロダクトパスポート・ENISA 提出管理を必要とする企業向けの商用コンパニオンです。OSS エンジンがプロトコルを開いたまま保ち、SaaS はスケールでの運用を売ります。

## ロードマップ

- [ ] `enisa dispatch --transport` プラグイン(SRP API 公開後)
- [ ] CSAF 変換プロファイル(`csaf_security_incident_response`、`informational_advisory`)
- [ ] OSV `severity` フィールドからの CVSS スコア伝播
- [ ] `match --offline-nvd` ローカル NVD ミラーアダプタ
- [ ] SBOM 差分(`openenisa diff before.json after.json`)によるリリースゲート

## コントリビューション

[CONTRIBUTING.md](CONTRIBUTING.md) を参照。パーサーサーフェスが成長領域です。新しい SBOM/VEX 形式は正規化モデルの背後の `src/ingest/` または `src/vex/` に追加され、1つのパーサーが下流の全段階を解放します。

## ライセンス

Apache-2.0。本プロジェクトは OASIS CSAF 2.0 JSON スキーマを Non-Assertion Mode ライセンスの下で、FIRST CVSS スキーマをそれぞれの規約の下で再配布します。[NOTICE](NOTICE) を参照。
