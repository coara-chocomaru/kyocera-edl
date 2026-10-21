# Kyocera EDL Tool

## 目次

- [基本構文](#基本構文)
- [共通オプション](#共通オプション)
- [コマンド一覧](#コマンド一覧)
- [`info` デバイス情報の表示](#info-デバイス情報の表示)
- [`dump` eMMCの読み出し](#dump-emmcの読み出し)
- [`flash` イメージの書き込み](#flash-イメージの書き込み)
- [`erase` パーティションの消去](#erase-パーティションの消去)
- [`verify` チェックサム検証](#verify-チェックサム検証)
- [MountGuard コマンド](#mountguard-コマンド)
- [内部専用引数](#内部専用引数)
- [ヘルプ](#ヘルプ)
- [実行前の注意](#実行前の注意)

## 基本構文

```bash
python tool.py [共通オプション] <コマンド> [コマンド別引数]
```

共通オプションは、基本的にコマンド名より前に指定してください。

## 共通オプション

| 引数 | 値の型 | 既定値 | 説明 |
|---|---|---|---|
| `--vid` | 16進数文字列 | `0x0482` | USB Vendor ID |
| `--pid` | 16進数文字列 | `0x0a7f` | USB Product ID |
| `--debug` | フラグ | 無効 | デバッグログを有効化 |
| `--no-guard` | フラグ | 無効 | MountGuardを自動起動せずに実行。主にWindows向け |
| `-h`, `--help` | フラグ | — | ヘルプを表示。`argparse` により自動設定 |

使用例：

```bash
python tool.py info
python tool.py --debug info
python tool.py --vid 0482 --pid 0a7f info
python tool.py --no-guard info
```

## コマンド一覧

| コマンド | 機能 | 個別引数 |
|---|---|---|
| `info` | デバイス状態、SecureBoot、GPTパーティション一覧を表示 | なし |
| `dump` | eMMC全体または指定パーティションを読み出す | `-o`, `-p`, `--full`, `--chunk`, `--delay` |
| `flash` | イメージをパーティションまたはeMMC全体へ書き込む | `-i`, `-p`, `--full`, `--clear-wp`, `--erase`, `--pad`, `--delay` |
| `erase` | 指定パーティションを消去する | `-p` |
| `verify` | ローカルイメージとデバイス側パーティションのチェックサムを比較 | `-p`, `-i` |
| `guard-start` | MountGuardを起動する（Windows専用） | なし |
| `guard-stop` | MountGuardを停止し、USBSTOR設定の復元を試みる（Windows専用） | なし |
| `guard-status` | MountGuardの状態を表示する（Windows専用） | なし |

## `info` デバイス情報の表示

### 構文

```bash
python tool.py info
```

SecureBoot状態、GPTパーティション一覧、総セクタ数、ディスク容量を表示します。

### 使用例

```bash
python tool.py info
python tool.py --debug info
```

個別の必須引数はありません。

## `dump` eMMCの読み出し

### 構文

```bash
python tool.py dump [引数]
```

### 引数

| 引数 | 値の型 | 必須 | 既定値 | 説明 |
|---|---|---|---|---|
| `-o`, `--output` | ファイル／ディレクトリのパス | いいえ | スクリプトのあるディレクトリに自動生成 | 出力ファイルまたは出力先ディレクトリ |
| `-p`, `--partition` | パーティション名 | 条件付き | なし | 読み出すパーティション。`--full` を指定しない場合に必要 |
| `--full` | フラグ | いいえ | 無効 | eMMC全体を読み出す |
| `--chunk` | 整数 | いいえ | Windows `128`、その他 `256` | 1回の読み出しで処理するセクタ数 |
| `--delay` | 浮動小数点数（秒） | いいえ | Windows `0.02`、その他 `0.0` | 各読み出し後の待機時間。待機処理はWindowsで有効 |

### 使用例

```bash
# eMMC全体を読み出す
python tool.py dump --full -o full_emmc.img

# systemパーティションを読み出す
python tool.py dump -p system

# 出力ディレクトリを指定する
python tool.py dump --full --output backups/

# チャンクサイズと待機時間を指定する
python tool.py dump --full --chunk 128 --delay 0.02 -o full_emmc.img
```

### 出力ファイル名

`--output` を省略すると、スクリプトと同じディレクトリに日時を含めた名前で保存します。

- 全体ダンプ：`YYYYMMDD_HHMMSS_full_emmc.img`
- パーティションダンプ：`YYYYMMDD_HHMMSS_<パーティション名>.img`

`--output` に既存ディレクトリを指定すると、そのディレクトリ内に自動生成したファイル名で保存します。ファイルパスを指定した場合は、そのパスが出力先になります。

## `flash` イメージの書き込み

### 構文

```bash
python tool.py flash [引数]
```

### 引数

| 引数 | 値の型 | 必須 | 既定値 | 説明 |
|---|---|---|---|---|
| `-i`, `--image` | ファイルパス | **はい** | なし | 書き込むイメージ／バイナリファイル |
| `-p`, `--partition` | パーティション名 | 条件付き | なし | 書き込み先。`--full` を指定しない場合に必要 |
| `--full` | フラグ | いいえ | 無効 | LBA 0からeMMC全体を書き換える |
| `--clear-wp` | フラグ | いいえ | 無効 | パーティション書き込み前に書き込み保護の解除を試みる |
| `--erase` | フラグ | いいえ | 無効 | パーティションへの書き込み前に消去する |
| `--pad` | フラグ | いいえ | 無効 | 入力データをセクタ境界までゼロ埋めする |
| `--delay` | 浮動小数点数（秒） | いいえ | Windows `0.02`、その他 `0.0` | 各書き込み後の待機時間。待機処理はWindowsで有効 |

### 使用例

```bash
# systemパーティションへ書き込む
python tool.py flash -p system -i system.img

# 書き込み前にパーティションを消去する
python tool.py flash -p system -i system.img --erase

# 書き込み保護の解除を試みる
python tool.py flash -p system -i system.img --clear-wp

# セクタ境界までゼロ埋めする
python tool.py flash -p system -i system.img --pad

# eMMC全体を書き換える
python tool.py flash --full -i full_emmc.img

# 書き込み後の待機時間を指定する
python tool.py flash -p system -i system.img --delay 0.02
```

`--full` の場合は全体書き込み処理が選ばれます。パーティション単位の `--clear-wp`、`--erase`、`--pad` は、その全体書き込み処理には適用されません。

## `erase` パーティションの消去

### 構文

```bash
python tool.py erase -p <パーティション名>
```

### 引数

| 引数 | 値の型 | 必須 | 説明 |
|---|---|---|---|
| `-p`, `--partition` | パーティション名 | **はい** | 消去するパーティション |

### 使用例

```bash
python tool.py erase -p system
python tool.py erase --partition userdata
```

GPTに指定パーティションが存在するかを確認してから消去処理を実行します。

## `verify` チェックサム検証

### 構文

```bash
python tool.py verify -p <パーティション名> -i <イメージファイル>
```

### 引数

| 引数 | 値の型 | 必須 | 説明 |
|---|---|---|---|
| `-p`, `--partition` | パーティション名 | **はい** | 検証するデバイス側パーティション |
| `-i`, `--image` | ファイルパス | **はい** | 比較対象となるローカルイメージ |

### 使用例

```bash
python tool.py verify -p system -i system.img
```

ローカルファイルとデバイス側パーティションのチェックサムを比較します。両方の値が取得できて一致すれば `[OK]`、不一致またはデバイス側の取得に失敗した場合は `[NG]` となります。

## MountGuard コマンド

MountGuardコマンドはWindows専用です

### 起動

```bash
python tool.py guard-start
```

MountGuardを管理者権限で起動し、常駐させます。※もしUAC確認が表示された場合は、許可してください。

### 停止

```bash
python tool.py guard-stop
```

MountGuardを停止し、保存されている元のUSBSTOR `Start` 値への復元。

### 状態確認

```bash
python tool.py guard-status
```

稼働状態、PID、USBSTORの現在値・保存された元の値、`ctypes` の準備状態、ログファイルの場所を表示します。

## 内部専用引数

| 引数 | 用途 | 通常の手動実行 |
|---|---|---|
| `--internal-guard-worker` | MountGuardのバックグラウンドワーカーを起動する内部引数 | 不要 |

この引数は公開コマンドとして `argparse` に登録されていません。内部処理が使用するため、通常は手動で指定しないでください。

## ヘルプ

```bash
# コマンド全体のヘルプ
python tool.py --help

# コマンドごとの引数
python tool.py dump --help
python tool.py flash --help
python tool.py erase --help
python tool.py verify --help
```

## 実行前の注意

- `flash --full` はeMMC全体を書き換える操作です。必要なデータのバックアップと対象デバイスの確認を行ってください。
- `erase` および `flash --erase` はデータを失う可能性があります。
- `--partition` に指定する名前は、実際にデバイスのGPTに存在する名前を使用してください。
- `--no-guard` はWindowsのMountGuard自動起動を抑止するオプションです。MountGuardによる保護処理も実行されなくなるため、目的を理解したうえで使用してください。
