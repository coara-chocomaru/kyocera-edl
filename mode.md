# 外部SDカードを使用した起動モードの切り替え

## 起動方法
まず最初にFAT32でフォーマットしたSDカードを用意する、容量はなんでもok

### Kyocera EDLモードで起動する場合

外部SDカードに [NOTPUSH](./NOTPUSH) を配置して端末を起動すると、Kyocera EDLモードになります。

### Fastbootモードで起動する場合

端末が対応していれば、[FASTBOOT](./FASTBOOT) だけを外部SDカードに配置して起動すると、Fastbootモードで起動します。

## 補足

どちらのモードも上手くいかない場合は、[CHKCODE](./CHKCODE) も一緒に外部SDカードに配置してください。

## 配置するファイル一覧

| ファイル名 | 用途 |
|---|---|
| [NOTPUSH](./NOTPUSH) | 外部SDカードに配置して起動すると、Kyocera EDLモードになる |
| [FASTBOOT](./FASTBOOT) | 端末が対応していれば、外部SDカードに配置して起動すると、Fastbootモードで起動する |
| [CHKCODE](./CHKCODE) | どちらのモードも上手くいかない場合に、一緒に外部SDカードへ配置する |

## 注意

- [FASTBOOT](./FASTBOOT) を配置してもFastbootモード起動は、端末が対応している場合に限ります。
- 起動モードの解除時は、SDカードを抜いてから長押しなどで再起動してください。
