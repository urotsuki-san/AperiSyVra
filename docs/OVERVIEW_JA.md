# AperiSyVra 日本語概要

AperiSyVra（アペリシヴラ）は、公開鍵暗号とKEMを研究するRustプロジェクトです。OrIsyVraとは姉妹関係ですが、こちらは公開鍵系統として独立しています。

## P1でできること

現在のP1には次の機能があります。

- 公開鍵と秘密鍵の生成
- 32バイト共有秘密のカプセル化と復号
- 16MiBまでのメッセージ暗号化と認証
- 鍵・暗号文・メッセージのバイナリ形式
- 復号失敗率と行列特性の測定
- Linux、Windows、macOS向けCI

## 仕組み

秘密鍵は32バイトの乱数シードです。このシードから、192行×256列の疎な検査行列を再生成します。

各列は7本の検査に接続します。

- 局所検査：4本
- 階層検査：2本
- 果樹園検査：1本

列を作る順序には、フィボナッチ置換、5方向の向き、互いに素な整数対、整数だけの黄金比型漸化式を使います。

秘密の検査行列へ可逆な行変換と列の並べ替えを行い、密な公開行列を作ります。暗号化側は公開行列から10列を選び、その排他的論理和を暗号文にします。

復号側は行変換を元へ戻し、疎な秘密行列でビット反転復号を行います。見つけた10列が公開行列上でも同じ暗号文になることを確認してから共有秘密を作ります。

## 使い方

鍵を作ります。

```bash
cargo run --locked --release -p aperisyvra -- keygen \
  --public alice.avpk \
  --secret alice.avsk
```

メッセージを暗号化します。

```bash
cargo run --locked --release -p aperisyvra -- seal \
  --public alice.avpk \
  --input message.txt \
  --output message.avm
```

復号します。

```bash
cargo run --locked --release -p aperisyvra -- open \
  --secret alice.avsk \
  --input message.avm \
  --output opened.txt
```

復号器を測定します。

```bash
cargo run --locked --release -p aperisyvra-analysis -- decoder-scan \
  --trials 10000 \
  --seed 7
```

## 現在の扱い

P1は研究用です。独立した暗号解析、具体的な安全性評価、サイドチャネル対策はまだ完了していません。秘密鍵ファイルも現時点では平文で保存されます。

まずは、秘密の疎行列による復号が安定して動くこと、公開行列から同等の構造を回収できないこと、復号失敗が情報漏えいにつながらないことを検証します。
