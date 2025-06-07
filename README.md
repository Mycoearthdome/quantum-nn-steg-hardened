# Quantum-NN Steganography Hardened

This project implements a **hardened, adaptive steganographic system** in Rust, designed to resist modern steganalysis techniques, including deep-learning-based classifiers, histogram analysis, and RS attacks.

## 🛡 Features

This system includes **five layers** of anti-detection defenses:

1. **Histogram-Preserving LSB (HPLSB)**  
   Prevents statistical anomalies in pixel histograms after bit embedding.

2. **Entropy-Weighted Embedding**
   Selects high-entropy (visually complex) regions using Sobel filtering and
   local Shannon entropy computed over a sliding window.

3. **Redundant Adaptive Embedding**  
   Each bit is embedded multiple times (e.g. 3×) and recovered by majority vote.

4. **Transform-Domain Embedding (DCT)**  
   Optionally embeds payload into mid-band JPEG-DCT coefficients for added stealth.

5. **Classifier-Resistant Statistical Masking**
   RS-safe, patch-based shuffling is applied at high stealth level to preserve global statistics while disrupting local correlations.

---

## ⚙ Installation

```bash
git clone git@github.com:Mycoearthdome/quantum-nn-steg-hardened.git
cd quantum-nn-steg-hardened
cargo build --release
```

---

## 🚀 Usage

### Embed a secret:

```bash
cargo run --release --   embed   --cover bird.jpeg   --secret secret.txt   --output stego.png   --password "your-passphrase"
```

### Extract a secret:

```bash
cargo run --release --   extract   --stego stego.png   --output extracted_secret.txt   --password "your-passphrase"
```

---

## 🧠 Advanced Options

- `--redundancy 3` — set bit redundancy factor (default: 3)
- `--domain lsb|lsb-match|dct` — select embedding domain
- `--stealth high|medium|low` — control aggressiveness of classifier masking
 - `--progress` — show progress bar and estimated time

When `--stealth high` is chosen, additional patch shuffling preserves image statistics while further confusing RS analysis.

---

## 📦 Features In Progress

- [x] HPLSB & entropy masking
- [x] Redundancy encoding
- [x] CLI framework
- [x] Mid-band DCT embedding
- [x] RS/Class-safe masking
- [ ] Embedded benchmarking suite (entropy, histogram diff, detectability)

---

## 🖼 Sample Assets

- `bird.jpeg` — cover image
- `secret.txt` — sample secret payload
- `stego.png` — output with embedded payload

---

## 📜 License

Apache 2.0

---

## 👁️‍🗨️ Disclaimer

This project is for **educational and research purposes only**. Use responsibly and legally.
