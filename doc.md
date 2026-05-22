# V2X CWE-674 防禦機制與 QoS 效能評估開發紀錄

**Documented Date:** 2026-05

## 1. 漏洞分析與特徵萃取 (Vulnerability Analysis & Signature Extraction)

**研究策略：差異分析 (Diff Analysis) 與資訊理論 (Information Theory)**
針對 Vanetza ASN.1 UPER 解析器面臨的 CWE-674 (Algorithmic Complexity / Infinite Recursion) 攻擊，我們放棄了依賴特定位元組 (如 `0x02`) 的死板特徵碼。基於正常密碼學憑證具備高熵值 (High Entropy) 的特性，我們確立了「任何長片段的連續重複字元，皆為攻擊者建構惡意深層巢狀結構的填充物 (Structural Padding)」的理論基礎。

**使用的關鍵指令：**

```bash
# 輸出正常封包的 Hex Dump 作為對照組
xxd input/cam_v3_certificate.dat > normal_hex.txt

# 輸出惡意封包的 Hex Dump 以尋找遞迴特徵 (如大量重複的 02)
xxd input-malware/poc_mtu_limit.bin > malware_hex.txt

# 直接在終端機預覽惡意封包內容
xxd input-malware/poc_mtu_limit.bin | head -n 20

```

---

## 2. O(N) 泛化預過濾器設計與模組化 (Generalized Pre-filter & Modularization)

**工程策略：模組化 (Modularization) 與關注點分離 (Separation of Concerns)**
為了保持主測試程式 (`qos_measure.cpp`) 的乾淨，並便於未來擴充，我們將防禦邏輯獨立封裝。過濾器採用 $O(N)$ 複雜度的單次遍歷演算法，只要偵測到「任何」字元連續重複超過安全閾值 (Threshold = 10)，即判定為結構炸彈並丟棄。

**使用的關鍵指令：**

```bash
# 在 Vanetza Unpatched 環境中編譯測試
cd ~/term-project/cse625_qos/vanetza_unpatched/build
make qos_measure -j$(nproc)

```

---

## 3. 自適應狀態機架構 (Adaptive Circuit Breaker FSM)

**系統策略：動態採樣防禦 (Dynamic Sampling Defense)**
為了解決過濾器對正常封包造成的「檢查稅 (Inspection Tax)」，我們實作了自適應熔斷器狀態機 (Finite State Machine, FSM)。

* **和平時期 (Peace Time):** 預設採用 5% 機率抽查，將正常流量的延遲開銷降至趨近於零。
* **受攻擊時期 (Under Attack):** 一旦 5% 抽查命中惡意特徵，系統瞬間切換至 100% 嚴格掃描，並啟動冷卻計數器 (Cooldown Timer = 10,000 封包)。期間若未再受攻擊，則自動降級回和平時期。

**修正的工程除錯 (Debugging)：**

* 引入 `<cstddef>` 解決 `size_t` 未定義問題。
* 使用 `vanetza::ByteBuffer buf_copy = buf; std::move(buf_copy);` 解決 `const` 參照無法被轉移 (Move Semantics) 的記憶體安全錯誤。
* 使用 `grep` 尋找源碼中隱藏的變數名稱：
```bash
grep -E "(int|double|float) " ~/term-project/cse625_qos/vanetza_unpatched/tools/qos-harness/qos_measure.cpp | head -n 20

```



---

## 4. 專案同步與自動化腳本 (Project Sync & Automation)

**工程策略：雙環境一致性 (Environment Consistency)**
確保 `unpatched` (未修補版) 與 `patched` (官方修補版) 兩個環境使用完全相同的測試程式與過濾器邏輯，以進行公平的 QoS 效能對照。

**使用的關鍵指令：**

```bash
# 定義環境變數
DIR_SRC=~/term-project/cse625_qos/vanetza_unpatched/tools/qos-harness
DIR_DST=~/term-project/cse625_qos/vanetza_patched/tools/qos-harness

# 同步核心程式碼至 Patched 環境
cp $DIR_SRC/pre_filter.hpp $DIR_DST/
cp $DIR_SRC/pre_filter.cpp $DIR_DST/
cp $DIR_SRC/qos_measure.cpp $DIR_DST/

# 重新編譯 Patched 環境
cd ~/term-project/cse625_qos/vanetza_patched/build
make qos_measure -j$(nproc)

# 執行自動化實驗腳本收集 CSV 數據
cd ~/term-project/cse625_qos/vanetza_unpatched/tools/qos-harness && ./run_experiments.sh
cd ~/term-project/cse625_qos/vanetza_patched/tools/qos-harness && ./run_experiments.sh

```

---

## 5. 學術級資料視覺化 (Academic Data Visualization)

**資料科學策略：一致性編碼 (Consistent Visual Encoding) 與絕對座標 (Unified Coordinates)**
為避免 `matplotlib` 自動縮放造成的視覺錯覺，我們強制鎖死所有圖表的比例尺 (Time Series Y-axis: 0~0.45 ms; CDF X-axis: $10^{-4}$ ~ 10.0 ms)。

**繪圖腳本 (`plot_master.py`) 關鍵功能：**

1. **五維度對照 (5-Dimensional Comparison):** 納入 Baseline, Unpatched, Official Patch, Unpatched+Filter, 以及 **Patched+Filter (縱深防禦 Defense-in-Depth)**。
2. **統計數據萃取 (Statistics Extraction):** 自動計算 Mean, Median, P99, P99.9, Max 延遲，並輸出 `qos_statistics_table.csv` 供論文製表使用。
3. **精準降落線 (P99 Drop-lines):** 在 CDF 對數圖 (Log Scale) 中，繪製 $Y=0.99$ 水平基準線，並自交點垂直降下虛線標註精確數值，避免肉眼誤判。

**使用的關鍵指令：**

```bash
# 於根目錄執行大師級繪圖與數據萃取腳本
cd ~/term-project/cse625_qos/
python plot_master.py

```

---

## 6. 核心學術論述整理 (Key Academic Arguments)

* **無特徵碼防禦 (Signature-less Defense):** 基於熵值分析的 $O(N)$ 掃描，完美防禦攻擊變種，執行時間 $< 0.001$ ms。
* **熔斷器機制 (Circuit Breaker):** 透過 5% 平時抽查，消除 95% 正常通訊的檢查稅 (Inspection Tax)，保證 QoS 穩定性。
* **第一擊懲罰 (First-Strike Penalty) 與縱深防禦:** FSM 架構在遭受攻擊初期，會有極少數封包鑽過 5% 抽查導致 Max Latency 飆高。將 Pre-filter 部署於網卡層 (NIC/Edge)，並搭配應用層的 Official Patch，即能達成兼顧效能與極端安全的**縱深防禦 (Hybrid Defense)**。