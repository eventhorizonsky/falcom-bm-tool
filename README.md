# falcom_bm

Falcom 图片容器 `._bm` 与归档 `.na` / `.ni` 的解包、封包工具。单文件，无第三方依赖（`--png` 需 Pillow）。

适用于 **Ys Chronicles I / II**（DotEmu 移动版与 PC 版）等使用 Falcom 自家压缩与归档格式的作品。

---

## 环境要求

- Python 3.7+
- 可选：Pillow（仅 `--png` 选项需要）

```bash
pip install Pillow
```

---

## 格式说明

### `._bm`（图片容器）

```
[u32 header = 8][u32 解压后总长度]
重复若干块:
    [u16 块长度][块长度-2 字节压缩数据][u8 末块标志]
[尾部附加字节]
```

- 压缩算法为 Falcom **BZip mode 2**（位流 LZ77，与 bzip2 无关）
- 每块解压后不超过 `0xFFF0` 字节
- 解压结果为标准 **8bpp BMP**

### `.na` / `.ni`（归档）

`.ni` 是索引（文件名表 + TOC），`.na` 是数据。条目名为 CP932 编码，`.Z` 结尾的条目为 zlib 压缩。本工具会自动解压 `.Z`。

---

## 算法参考来源

本工具是以下开源实现的 Python 移植 / 再实现，特此致谢。

### 1. Falcom BZip 压缩（mode 2）

> **Aureole-Suite / Falcompress**
> <https://github.com/Aureole-Suite/Falcompress>
> 许可：MIT OR Apache-2.0

对照文件：

- `src/bzip/decompress.rs` — 解压器
- `src/bzip/compress/mode2.rs` — 压缩器
- `src/bzip/mod.rs` — 块帧格式

该实现明确以"产生与 Falcom 官方工具完全相同的位流"为目标。本工具的位流布局、压缩器匹配搜索与终止序列均据此实现，包括：

- 位流首字仅使用高 8 位（其后每字用满 16 位）
- 长度 / 偏移的位分配与转义规则
- 压缩器的匹配搜索窗口与贪心策略

产物对照：`falcom_bm.py verify` 对原始文件解包后重新封包，输出与输入**逐字节一致**。

### 2. `.na` / `.ni` 归档

> **Kyuuhachi — Ys I/II/Origin/VI extractor**
> <https://gist.github.com/Kyuuhachi/42b6acd38a99f7cc8d924286617a9c02>

对照：TOC / 名称表的反混淆算法（`0x7C53F961 * 0x3D09^n` 递减）与 `.Z` 条目的 zlib 处理。

### 3. 相关项目

- [TwnKey/YCTT](https://github.com/TwnKey/YCTT) — Ys Chronicles 翻译工具集（字体、图片、文本）
- [Darkmet98/AdolTranslator](https://github.com/Darkmet98/AdolTranslator) — Ys I 文本与图形翻译工具
- [spillerrec/skytrails-replacer](https://github.com/spillerrec/skytrails-replacer) — Falcom 压缩格式的早期文档与实现

---

## 用法

### 1. 解包单个 `._bm`

```bash
python falcom_bm.py extract bk1p._bm
# -> bk1p.bmp
```

指定输出路径，并同时生成 PNG 预览：

```bash
python falcom_bm.py extract bk1p._bm -o out/bk1p.bmp --png
```

### 2. 解包整个目录

```bash
python falcom_bm.py extract ./bmp -o ./extracted --png
```

或：

```bash
python falcom_bm.py batch-extract ./bmp -o ./extracted --png
```

### 3. 封包单个 BMP

需要提供**原始 `._bm` 作为模板**，块的划分会沿用模板：

```bash
python falcom_bm.py pack edited.bmp --template bk1p._bm -o ./new
```

若不指定 `--template`，默认查找同名 `._bm`。

### 4. 批量封包

```bash
python falcom_bm.py batch-pack ./edited --template-dir ./orig_bm -o ./new_bm
```

约定：`./edited` 中的 `NAME.bmp` 对应 `./orig_bm/NAME._bm`。

### 5. 无损校验

解包后立刻重新封包，与原文件逐字节比对。修改前建议先跑一遍：

```bash
python falcom_bm.py verify bk1p._bm end_text._bm
```

或批量（bash）：

```bash
python falcom_bm.py verify *._bm
```

输出：

```
bk1p._bm                     解压  131640  重建   75072  完全一致
```

`完全一致` 表示该文件可安全往返，工具与游戏使用的算法行为一致。

### 6. 归档 `.na` / `.ni`

列出内容：

```bash
python falcom_bm.py archive-list data_ys1.na --filter bk
```

提取（可按名称过滤，`.Z` 自动解压）：

```bash
python falcom_bm.py archive-extract data_ys1.na -o ./pc_bmp --filter "bmp\bk"
```

---

## 参数说明

| 参数 | 说明 |
|---|---|
| `-o`, `--output` | 输出文件或目录 |
| `--png` | 同时输出 PNG（需 Pillow） |
| `--template` | 封包时使用的原始 `._bm` |
| `--template-dir` | 批量封包时原始 `._bm` 所在目录 |
| `--filter` | 归档操作时按名称子串过滤 |
| `--no-fit-header` | 长度不一致时报错，不自动修正 BMP 头 |

---

## 关于 BMP 长度不一致

`._bm` 解出的 BMP 长度由原文件决定，个别文件的像素数据可能比 BMP 头声明的尺寸略短（游戏按固定尺寸解析）。

封包时若 BMP 长度与模板解压长度不一致，工具默认会：

1. 截断或补零到模板长度
2. 修正 BMP 头中的**文件大小**（偏移 `+2`）与**像素数据大小**（偏移 `+34`）字段，使其自洽

这样产出的文件能被标准 BMP 解析器正常读取。若希望长度不符时直接报错，加 `--no-fit-header`。

---

## 典型工作流

```bash
# 1. 备份 + 解包
cp bk1p._bm bk1p._bm.bak
python falcom_bm.py extract ./bmp -o ./edit --png

# 2. 用图像编辑器修改 ./edit/*.bmp（保持 8bpp、尺寸与调色板不变）

# 3. 封包
python falcom_bm.py batch-pack ./edit --template-dir ./bmp -o ./patched

# 4. 校验（可选：对未修改的副本应完全一致）
python falcom_bm.py verify ./bmp/bk1p._bm
```

---

## 注意事项

- 封包时**不要改变图像尺寸与位深**，并按模板长度对齐像素数据。
- 保留原文件的**块划分**（由 `--template` 自动处理），块数量与顺序会原样沿用。
- 修改前请务必备份原始文件。

---

## 许可

本工具代码以 **MIT License** 发布。

`compress()` / `decompress()` 参考并移植自 [Aureole-Suite/Falcompress](https://github.com/Aureole-Suite/Falcompress)（MIT OR Apache-2.0），
归档解析参考 [Kyuuhachi 的 extractor gist](https://gist.github.com/Kyuuhachi/42b6acd38a99f7cc8d924286617a9c02)，
相应署名与许可声明保留于源码文件头部。
