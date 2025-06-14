use std::fs::File;
use std::io::{Read, Write};

use clap::{Parser, Subcommand, ValueEnum};
use image::{DynamicImage, GenericImageView, Rgba, RgbaImage};
use rand::{Rng, SeedableRng};
use rand::seq::SliceRandom;
use rand::rngs::StdRng;
use sha2::{Sha256, Sha512, Digest};
use crc32fast::Hasher as Crc32Hasher;
use bzip2::read::{BzEncoder, BzDecoder};
use bzip2::Compression;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Embed {
        #[arg(long)]
        cover: String,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 3)]
        redundancy: usize,
        #[arg(long, value_enum, default_value_t = Domain::Lsb)]
        domain: Domain,
        #[arg(long, value_enum, default_value_t = StealthLevel::Medium)]
        stealth: StealthLevel,
        #[arg(long, default_value_t = false)]
        progress: bool,
        #[arg(
            long,
            default_value_t = 1,
            help = "Number of masking attempts; the run with the lowest detection score is kept",
        )]
        optimize: usize,
    },
    Extract {
        #[arg(long)]
        stego: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 3)]
        redundancy: usize,
        #[arg(long, value_enum, default_value_t = Domain::Lsb)]
        domain: Domain,
        #[arg(long, default_value_t = false)]
        progress: bool,
    },
    Detect {
        #[arg(long)]
        image: String,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Domain {
    Lsb,
    LsbMatch,
}

#[derive(Copy, Clone, ValueEnum)]
enum StealthLevel {
    Low,
    Medium,
    High,
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1)).collect()
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8).map(|chunk| chunk.iter().fold(0, |acc, &b| (acc << 1) | b)).collect()
}

fn xor_bits(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

fn bz2_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = BzEncoder::new(data, Compression::best());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed).unwrap();
    compressed
}

fn bz2_decompress(data: &[u8]) -> Vec<u8> {
    let mut decoder = BzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    decompressed
}

fn generate_bits_fast(n: usize, password: &str) -> Vec<u8> {
    let mut bits = Vec::with_capacity(n);
    let mut counter: u64 = 0;
    while bits.len() < n {
        let mut hasher = Sha512::new();
        hasher.update(password.as_bytes());
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        for byte in digest {
            for i in (0..8).rev() {
                if bits.len() == n { break; }
                bits.push((byte >> i) & 1);
            }
            if bits.len() == n { break; }
        }
        counter += 1;
    }
    bits
}

fn int_to_bits(val: usize, bits: usize) -> Vec<u8> {
    (0..bits).rev().map(|i| ((val >> i) & 1) as u8).collect()
}

fn bits_to_int(bits: &[u8]) -> usize {
    bits.iter().fold(0, |acc, &b| (acc << 1) | b as usize)
}

fn rgb_to_ycbcr(r: u8, g: u8, b: u8) -> (f64, f64, f64) {
    let r = r as f64;
    let g = g as f64;
    let b = b as f64;
    // Coefficients from JPEG File Interchange Format (Version 1.02)
    let y  = 0.299_f64 * r + 0.587_f64 * g + 0.114_f64 * b;
    let cb = -0.168736_f64 * r - 0.331264_f64 * g + 0.5_f64 * b + 128.0;
    let cr = 0.5_f64 * r - 0.418688_f64 * g - 0.081312_f64 * b + 128.0;
    (y, cb, cr)
}

fn ycbcr_to_rgb(y: f64, cb: f64, cr: f64) -> (u8, u8, u8) {
    let r = (y + 1.402_f64 * (cr - 128.0)).round().clamp(0.0, 255.0);
    let g = (y - 0.344136_f64 * (cb - 128.0) - 0.714136_f64 * (cr - 128.0))
        .round()
        .clamp(0.0, 255.0);
    let b = (y + 1.772_f64 * (cb - 128.0)).round().clamp(0.0, 255.0);
    (r as u8, g as u8, b as u8)
}


fn compute_capacity(img: &DynamicImage, domain: Domain, redundancy: usize) -> usize {
    match domain {
        Domain::Lsb => img.to_rgba8().as_flat_samples().samples.len() / (2 * redundancy),
        Domain::LsbMatch => img.to_rgba8().as_flat_samples().samples.len() / redundancy,
    }
}

fn add_crc_and_len(bits: &[u8]) -> Vec<u8> {
    let len = bits.len();
    let mut hasher = Crc32Hasher::new();
    hasher.update(&bits_to_bytes(bits));
    let crc = hasher.finalize();
    let mut out = int_to_bits(len, 32);
    out.extend(int_to_bits(crc as usize, 32));
    out.extend_from_slice(bits);
    out
}

fn check_crc_and_len(bits: &[u8]) -> Option<Vec<u8>> {
    if bits.len() < 64 {
        return None;
    }
    let length = bits_to_int(&bits[..32]);
    let crc_expected = bits_to_int(&bits[32..64]);
    if length > bits.len().saturating_sub(64) {
        return None;
    }
    let data = &bits[64..64 + length];
    let mut hasher = Crc32Hasher::new();
    hasher.update(&bits_to_bytes(data));
    if hasher.finalize() as usize == crc_expected {
        Some(data.to_vec())
    } else {
        None
    }
}



fn adaptive_embed_lsb(img: &DynamicImage, bits: &[u8], password: &str, redundancy: usize, show_progress: bool) -> RgbaImage {
    let mut rgba = img.to_rgba8();
    let flat = rgba.as_flat_samples_mut().samples;

    // use deterministic pseudorandom positions derived only from the password
    let mut rng = StdRng::seed_from_u64(u64::from_le_bytes(Sha256::digest(password.as_bytes())[..8].try_into().unwrap()));

    let mut bit_index = 0;
    let capacity = flat.len();
    let pb = if show_progress {
        let bar = ProgressBar::new((bits.len() as u64).min((capacity / (2 * redundancy)) as u64));
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    let mut positions: Vec<usize> = (0..capacity/4).map(|p| p*4).collect();
    positions.shuffle(&mut rng);

    // Precompute which indices will be used for embedding so we avoid
    // swapping with them and corrupting future bits.
    let mut reserved = vec![false; capacity];
    for pos in positions.iter().take(bits.len()) {
        for i in 0..redundancy {
            reserved[(pos + i) % capacity] = true;
        }
    }

    let mut used = vec![false; capacity];
    while bit_index < bits.len() && bit_index < capacity / (2 * redundancy) {
        let pos = positions[bit_index % positions.len()];
        for i in 0..redundancy {
            let idx1 = (pos + i) % capacity;
            used[idx1] = true;
            let orig = flat[idx1];
            let new_val = (orig & 0xFE) | bits[bit_index];
            if orig == new_val { continue; }

            let mut idx2 = (idx1 + 1) % capacity;
            let mut steps = 0;
            while steps < capacity {
                if !reserved[idx2] && !used[idx2] && flat[idx2] == new_val {
                    break;
                }
                idx2 = (idx2 + 1) % capacity;
                steps += 1;
            }
            if steps < capacity && idx2 != idx1 {
                flat[idx1] = new_val;
                flat[idx2] = orig;
                used[idx2] = true;
            } else {
                flat[idx1] = new_val;
            }
        }
        bit_index += 1;
        if let Some(ref bar) = pb { bar.inc(1); }
    }

    if let Some(bar) = pb { bar.finish_with_message("Embedding complete"); }
    rgba
}

fn adaptive_embed_lsb_match(img: &DynamicImage, bits: &[u8], password: &str, redundancy: usize, show_progress: bool) -> RgbaImage {
    let mut rgba = img.to_rgba8();
    let flat = rgba.as_flat_samples_mut().samples;

    let digest = Sha256::digest(password.as_bytes());
    let mut rng_pos = StdRng::seed_from_u64(u64::from_le_bytes(digest[..8].try_into().unwrap()));
    let mut rng_mod = StdRng::seed_from_u64(u64::from_le_bytes(digest[8..16].try_into().unwrap()));

    let mut bit_index = 0;
    let capacity = flat.len();
    let pb = if show_progress {
        let bar = ProgressBar::new((bits.len() as u64).min((capacity / redundancy) as u64));
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    let mut positions: Vec<usize> = (0..capacity/4).map(|p| p*4).collect();
    positions.shuffle(&mut rng_pos);
    while bit_index < bits.len() && bit_index < capacity / redundancy {
        let pos = positions[bit_index % positions.len()];
        for i in 0..redundancy {
            let idx = (pos + i) % capacity;
            let byte = &mut flat[idx];
            let bit = bits[bit_index];
            if (*byte & 1) != bit {
                if *byte == 0 { *byte = 1; }
                else if *byte == 255 { *byte = 254; }
                else if rng_mod.gen_bool(0.5) { *byte = byte.wrapping_add(1); } else { *byte = byte.wrapping_sub(1); }
            }
        }
        bit_index += 1;
        if let Some(ref bar) = pb { bar.inc(1); }
    }

    if let Some(bar) = pb { bar.finish_with_message("Embedding complete"); }
    rgba
}

fn adaptive_extract_lsb(img: &DynamicImage, bits_len: usize, password: &str, redundancy: usize, show_progress: bool) -> Vec<u8> {
    let rgba = img.to_rgba8();
    let flat = rgba.as_flat_samples().samples;
    let mut rng = StdRng::seed_from_u64(u64::from_le_bytes(Sha256::digest(password.as_bytes())[..8].try_into().unwrap()));

    let mut bits = Vec::with_capacity(bits_len);
    let pb = if show_progress {
        let bar = ProgressBar::new(bits_len as u64);
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    let mut positions: Vec<usize> = (0..flat.len()/4).map(|p| p*4).collect();
    positions.shuffle(&mut rng);
    for i in 0..bits_len {
        let pos = positions[i % positions.len()];
        let mut votes = [0, 0];
        for i in 0..redundancy {
            let idx = (pos + i) % flat.len();
            let bit = flat[idx] & 1;
            votes[bit as usize] += 1;
        }
        bits.push(if votes[1] > votes[0] { 1 } else { 0 });
        if let Some(ref bar) = pb { bar.inc(1); }
    }

    if let Some(bar) = pb { bar.finish_with_message("Extraction complete"); }
    bits
}



fn mask_low(img: &mut RgbaImage, rng: &mut StdRng) {
    for p in img.pixels_mut() {
        let jitter: i16 = rng.gen_range(-1..=1);
        p.0[0] = (p.0[0] as i16 + jitter).clamp(0, 255) as u8;
        p.0[1] = (p.0[1] as i16 + jitter).clamp(0, 255) as u8;
        p.0[2] = (p.0[2] as i16 + jitter).clamp(0, 255) as u8;
    }
}

fn mask_medium(img: &mut RgbaImage, rng: &mut StdRng) {
    mask_low(img, rng);
    let blurred = image::imageops::blur(img, 0.5);
    *img = blurred;
}

fn mask_rs_safe(img: &mut RgbaImage, rng: &mut StdRng) {
    let (width, height) = img.dimensions();
    let block = 4;
    for by in (0..height).step_by(block as usize) {
        for bx in (0..width).step_by(block as usize) {
            let mut patch = Vec::new();
            for y in 0..block {
                for x in 0..block {
                    let nx = bx + x;
                    let ny = by + y;
                    if nx < width && ny < height {
                        patch.push(*img.get_pixel(nx, ny));
                    }
                }
            }
            patch.shuffle(rng);
            let mut iter = patch.into_iter();
            for y in 0..block {
                for x in 0..block {
                    let nx = bx + x;
                    let ny = by + y;
                    if nx < width && ny < height {
                        if let Some(px) = iter.next() {
                            img.put_pixel(nx, ny, px);
                        }
                    }
                }
            }
        }
    }
}

fn mask_high(img: &mut RgbaImage, rng: &mut StdRng) {
    for _ in 0..2 {
        mask_low(img, rng);
        let blurred = image::imageops::blur(img, 1.0);
        *img = blurred;
    }
    mask_rs_safe(img, rng);
}

fn mask_image(img: &mut RgbaImage, level: StealthLevel, password: &str, attempt: u64) {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(attempt.to_be_bytes());
    let digest = hasher.finalize();
    let mut rng = StdRng::seed_from_u64(u64::from_le_bytes(digest[..8].try_into().unwrap()));
    match level {
        StealthLevel::Low => mask_low(img, &mut rng),
        StealthLevel::Medium => mask_medium(img, &mut rng),
        StealthLevel::High => mask_high(img, &mut rng),
    }
}

fn detect_lsb_randomness(img: &DynamicImage) -> f64 {
    let bytes = img.to_rgba8().into_raw();
    let mut counts = [0usize; 2];
    for b in bytes {
        counts[(b & 1) as usize] += 1;
    }
    let total = (counts[0] + counts[1]) as f64;
    if total == 0.0 { return 0.0; }
    let expected = total / 2.0;
    ((counts[0] as f64 - expected).powi(2) / expected) +
        ((counts[1] as f64 - expected).powi(2) / expected)
}

fn detect_lsb_match(img: &DynamicImage) -> f64 {
    let bytes = img.to_rgba8().into_raw();
    if bytes.len() < 2 { return 0.0; }
    let mut diff1 = 0usize;
    for i in 1..bytes.len() {
        if bytes[i].abs_diff(bytes[i-1]) == 1 { diff1 += 1; }
    }
    diff1 as f64 / (bytes.len() - 1) as f64
}

fn run_adversarial_tests(img: &DynamicImage) -> f64 {
    let lsb_chi = detect_lsb_randomness(img);
    let lsb_match_rate = detect_lsb_match(img);
    println!("[INFO] LSB chi-square statistic: {:.4}", lsb_chi);
    println!("[INFO] LSB-match diff rate: {:.4}", lsb_match_rate);

    fn logistic(x: f64) -> f64 { 1.0 / (1.0 + (-x).exp()) }

    let lsb_score = logistic((lsb_chi - 2.0) / 2.0);
    let lsb_match_score = logistic((lsb_match_rate - 0.01) / 0.01);
    let confidence = (lsb_score + lsb_match_score) / 2.0 * 100.0;
    println!(
        "[INFO] Approximate likelihood of recoverable hidden data: {:.1}%",
        confidence
    );
    confidence
}

fn embed_with_optimization(
    cover_img: &DynamicImage,
    bits: &[u8],
    password: &str,
    domain: Domain,
    redundancy: usize,
    stealth: StealthLevel,
    attempts: usize,
    progress: bool,
) -> RgbaImage {
    let mut best_img = None;
    let mut best_score = f64::INFINITY;
    for attempt in 0..attempts {
        let mut img = cover_img.to_rgba8();
        mask_image(&mut img, stealth, password, attempt as u64);
        let masked = DynamicImage::ImageRgba8(img);
        let stego = match domain {
            Domain::Lsb => adaptive_embed_lsb(&masked, bits, password, redundancy, progress && attempts==1),
            Domain::LsbMatch => adaptive_embed_lsb_match(&masked, bits, password, redundancy, progress && attempts==1),
        };
        let score = run_adversarial_tests(&DynamicImage::ImageRgba8(stego.clone()));
        if score < best_score {
            best_score = score;
            best_img = Some(stego);
        }
    }
    println!("[INFO] Selected embedding with score {:.1}%", best_score);
    best_img.expect("No embedding produced")
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Embed { cover, secret, output, password, redundancy, domain, stealth, progress, optimize } => {
            let cover_img = image::open(&cover).expect("Failed to open cover image");

            // Apply classifier-resistant masking prior to embedding so that
            // the embedded bits are not altered by the masking operations.
            let mut secret_file = File::open(&secret).expect("Failed to open secret file");
            let mut content = Vec::new();
            secret_file.read_to_end(&mut content).unwrap();

            let compressed = bz2_compress(&content);
            let raw_bits = bytes_to_bits(&compressed);
            let final_bits = add_crc_and_len(&raw_bits);

            let capacity = compute_capacity(&cover_img, domain, redundancy);
            if final_bits.len() > capacity {
                println!("[ERROR] Secret too large for cover image with current settings ({} bits > {} bits).", final_bits.len(), capacity);
                return;
            }

            let key = generate_bits_fast(final_bits.len(), &password);
            let masked_bits = xor_bits(&final_bits, &key);

            let stego_img = embed_with_optimization(&cover_img, &masked_bits, &password, domain, redundancy, stealth, optimize, progress);

            // stego_img already contains the masking transformations, so we can
            // save it directly. When saving as JPEG, use quality 100 to
            // minimize loss so DCT-embedded bits remain intact.
            use std::path::Path;
            let out_path = Path::new(&output);
            match out_path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()) {
                Some(ext) if ext == "jpg" || ext == "jpeg" => {
                    let dynimg = image::DynamicImage::ImageRgba8(stego_img.clone());
                    let mut file = File::create(out_path).unwrap();
                    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut file, 100);
                    encoder.encode_image(&dynimg).unwrap();
                }
                _ => {
                    stego_img.save(out_path).unwrap();
                }
            }
        },
        Commands::Extract { stego, output, password, redundancy, domain, progress } => {
            let stego_loaded = image::open(&stego).expect("Failed to open stego image");
            let bits_len;
            {
                let mut secret_file = File::open(&stego).unwrap();
                secret_file.read_to_end(&mut Vec::new()).unwrap();
            }
            // We don't know exact length yet; extract up to the embedding capacity
            let capacity = compute_capacity(&stego_loaded, domain, redundancy);
            bits_len = capacity;

            let extracted_bits = match domain {
                Domain::Lsb => adaptive_extract_lsb(&stego_loaded, bits_len, &password, redundancy, progress),
                Domain::LsbMatch => adaptive_extract_lsb(&stego_loaded, bits_len, &password, redundancy, progress),
            };
            let key = generate_bits_fast(bits_len, &password);
            let unmasked_bits = xor_bits(&extracted_bits[..bits_len], &key);
            if let Some(payload_bits) = check_crc_and_len(&unmasked_bits) {
                let bytes = bits_to_bytes(&payload_bits);
                let decompressed = bz2_decompress(&bytes);
                let mut output_file = File::create(&output).unwrap();
                output_file.write_all(&decompressed).unwrap();
                println!("[INFO] Extraction complete. File saved as {}", output);
            } else {
                println!("[ERROR] CRC check failed or no payload found.");
            }
        }
        Commands::Detect { image } => {
            let img = image::open(&image).expect("Failed to open image");
            run_adversarial_tests(&img);
        }
    }
}

