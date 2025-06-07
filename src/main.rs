use std::fs::File;
use std::io::{Read, Write};

use clap::{Parser, Subcommand, ValueEnum};
use image::{DynamicImage, GenericImageView, RgbaImage, Luma};
use imageproc::gradients::sobel_gradient_map;
use rand::{Rng, SeedableRng};
use rand::seq::SliceRandom;
use rand::distributions::{WeightedIndex, Distribution};
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
}

#[derive(Copy, Clone, ValueEnum)]
enum Domain {
    Lsb,
    Dct,
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
    let mut counter: u32 = 0;
    let mut hasher = Sha512::new();
    while bits.len() < n {
        hasher.update(password.as_bytes());
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize_reset();
        for byte in digest {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
                if bits.len() == n {
                    break;
                }
            }
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
    let length = bits_to_int(&bits[..32]);
    let crc_expected = bits_to_int(&bits[32..64]);
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
    let gray = img.to_luma8();
    let gradient = sobel_gradient_map(&gray, |p| Luma([p[0] as u16]));

    let flat = rgba.as_flat_samples_mut().samples;
    let mut weights: Vec<f64> = gradient.pixels().map(|p| p[0] as f64 + 1.0).collect();
    let total_weight: f64 = weights.iter().sum();
    weights.iter_mut().for_each(|w| *w /= total_weight);

    let mut rng = StdRng::seed_from_u64(u64::from_le_bytes(Sha256::digest(password.as_bytes())[..8].try_into().unwrap()));
    let dist = WeightedIndex::new(&weights).unwrap();

    let mut bit_index = 0;
    let capacity = flat.len();
    let pb = if show_progress {
        let bar = ProgressBar::new((bits.len() as u64).min((capacity / redundancy) as u64));
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    while bit_index < bits.len() && bit_index < capacity / redundancy {
        let pos = dist.sample(&mut rng) * 4;
        for i in 0..redundancy {
            let idx = (pos + i) % capacity;
            flat[idx] = (flat[idx] & 0xFE) | bits[bit_index];
        }
        bit_index += 1;
        if let Some(ref bar) = pb { bar.inc(1); }
    }

    if let Some(bar) = pb { bar.finish_with_message("Embedding complete"); }
    rgba
}

fn adaptive_embed_lsb_match(img: &DynamicImage, bits: &[u8], password: &str, redundancy: usize, show_progress: bool) -> RgbaImage {
    let mut rgba = img.to_rgba8();
    let gray = img.to_luma8();
    let gradient = sobel_gradient_map(&gray, |p| Luma([p[0] as u16]));

    let flat = rgba.as_flat_samples_mut().samples;
    let mut weights: Vec<f64> = gradient.pixels().map(|p| p[0] as f64 + 1.0).collect();
    let total_weight: f64 = weights.iter().sum();
    weights.iter_mut().for_each(|w| *w /= total_weight);

    let mut rng = StdRng::seed_from_u64(u64::from_le_bytes(Sha256::digest(password.as_bytes())[..8].try_into().unwrap()));
    let dist = WeightedIndex::new(&weights).unwrap();

    let mut bit_index = 0;
    let capacity = flat.len();
    let pb = if show_progress {
        let bar = ProgressBar::new((bits.len() as u64).min((capacity / redundancy) as u64));
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    while bit_index < bits.len() && bit_index < capacity / redundancy {
        let pos = dist.sample(&mut rng) * 4;
        for i in 0..redundancy {
            let idx = (pos + i) % capacity;
            let byte = &mut flat[idx];
            let bit = bits[bit_index];
            if (*byte & 1) != bit {
                if *byte == 0 { *byte = 1; }
                else if *byte == 255 { *byte = 254; }
                else if rng.gen_bool(0.5) { *byte = byte.wrapping_add(1); } else { *byte = byte.wrapping_sub(1); }
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
    let gray = img.to_luma8();
    let gradient = sobel_gradient_map(&gray, |p| Luma([p[0] as u16]));

    let mut weights: Vec<f64> = gradient.pixels().map(|p| p[0] as f64 + 1.0).collect();
    let total_weight: f64 = weights.iter().sum();
    weights.iter_mut().for_each(|w| *w /= total_weight);

    let mut rng = StdRng::seed_from_u64(u64::from_le_bytes(Sha256::digest(password.as_bytes())[..8].try_into().unwrap()));
    let dist = WeightedIndex::new(&weights).unwrap();

    let mut bits = Vec::with_capacity(bits_len);
    let pb = if show_progress {
        let bar = ProgressBar::new(bits_len as u64);
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    for _ in 0..bits_len {
        let pos = dist.sample(&mut rng) * 4;
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

// Simplified transform-domain embedding using DCT on 8x8 blocks
fn dct_embed(img: &DynamicImage, bits: &[u8], _password: &str, redundancy: usize, show_progress: bool) -> RgbaImage {
    use rustdct::{DctPlanner};
    let mut rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    let mut planner = DctPlanner::new();
    let dct = planner.plan_dct2(8);
    let idct = planner.plan_dct3(8);

    let capacity = (width / 8) * (height / 8);
    let pb = if show_progress {
        let bar = ProgressBar::new((bits.len() as u64).min(capacity as u64));
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    let mut bit_index = 0;

    for by in 0..height/8 {
        for bx in 0..width/8 {
            if bit_index >= bits.len() { break; }
            let mut block_r = [[0f32;8];8];
            let mut block_g = [[0f32;8];8];
            let mut block_b = [[0f32;8];8];
            for y in 0..8 {
                for x in 0..8 {
                    let px = rgba.get_pixel(bx*8 + x, by*8 + y);
                    block_r[y as usize][x as usize] = px[0] as f32;
                    block_g[y as usize][x as usize] = px[1] as f32;
                    block_b[y as usize][x as usize] = px[2] as f32;
                }
            }
            // apply 2D DCT
            for row in &mut block_r { dct.process_dct2(row); }
            for row in &mut block_g { dct.process_dct2(row); }
            for row in &mut block_b { dct.process_dct2(row); }
            for x in 0..8 {
                let mut col = [0f32;8];
                for y in 0..8 { col[y as usize] = block_r[y as usize][x as usize]; }
                dct.process_dct2(&mut col);
                for y in 0..8 { block_r[y as usize][x as usize] = col[y as usize]; }
                for y in 0..8 { col[y as usize] = block_g[y as usize][x as usize]; }
                dct.process_dct2(&mut col);
                for y in 0..8 { block_g[y as usize][x as usize] = col[y as usize]; }
                for y in 0..8 { col[y as usize] = block_b[y as usize][x as usize]; }
                dct.process_dct2(&mut col);
                for y in 0..8 { block_b[y as usize][x as usize] = col[y as usize]; }
            }

            // modify mid-band coefficient (3,4) with redundancy
            for i in 0..redundancy {
                let bit = bits[bit_index];
                let coeff_idx = ((3 + i) % 8, (4 + i) % 8);
                let (cx, cy) = coeff_idx;
                let mut val = block_r[cy][cx].round() as i32;
                val = (val & !1) | bit as i32;
                block_r[cy][cx] = val as f32;
            }
            bit_index += 1;
            if let Some(ref bar) = pb { bar.inc(1); }

            // inverse DCT
            for x in 0..8 {
                let mut col = [0f32;8];
                for y in 0..8 { col[y as usize] = block_r[y as usize][x as usize]; }
                idct.process_dct3(&mut col);
                for y in 0..8 { block_r[y as usize][x as usize] = col[y as usize]; }
                for y in 0..8 { col[y as usize] = block_g[y as usize][x as usize]; }
                idct.process_dct3(&mut col);
                for y in 0..8 { block_g[y as usize][x as usize] = col[y as usize]; }
                for y in 0..8 { col[y as usize] = block_b[y as usize][x as usize]; }
                idct.process_dct3(&mut col);
                for y in 0..8 { block_b[y as usize][x as usize] = col[y as usize]; }
            }
            for row in &mut block_r { idct.process_dct3(row); }
            for row in &mut block_g { idct.process_dct3(row); }
            for row in &mut block_b { idct.process_dct3(row); }

            for y in 0..8 {
                for x in 0..8 {
                    let r = block_r[y as usize][x as usize].round().clamp(0.0, 255.0) as u8;
                    let g = block_g[y as usize][x as usize].round().clamp(0.0, 255.0) as u8;
                    let b = block_b[y as usize][x as usize].round().clamp(0.0, 255.0) as u8;
                    let px = rgba.get_pixel_mut(bx*8 + x, by*8 + y);
                    *px = image::Rgba([r, g, b, px[3]]);
                }
            }
            if bit_index >= bits.len() { break; }
        }
        if bit_index >= bits.len() { break; }
    }
    if let Some(bar) = pb { bar.finish_with_message("Embedding complete"); }
    rgba
}

fn dct_extract(img: &DynamicImage, bits_len: usize, _password: &str, redundancy: usize, show_progress: bool) -> Vec<u8> {
    use rustdct::DctPlanner;
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    let mut planner = DctPlanner::new();
    let dct = planner.plan_dct2(8);

    let mut bits = Vec::with_capacity(bits_len);
    let pb = if show_progress {
        let bar = ProgressBar::new(bits_len as u64);
        bar.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap());
        Some(bar)
    } else { None };

    let mut bit_index = 0;
    for by in 0..height/8 {
        for bx in 0..width/8 {
            if bit_index >= bits_len { break; }
            let mut block_r = [[0f32;8];8];
            for y in 0..8 {
                for x in 0..8 {
                    let px = rgba.get_pixel(bx*8 + x, by*8 + y);
                    block_r[y as usize][x as usize] = px[0] as f32;
                }
            }
            for row in &mut block_r { dct.process_dct2(row); }
            for x in 0..8 {
                let mut col = [0f32;8];
                for y in 0..8 { col[y as usize] = block_r[y as usize][x as usize]; }
                dct.process_dct2(&mut col);
                for y in 0..8 { block_r[y as usize][x as usize] = col[y as usize]; }
            }
            let mut votes = [0,0];
            for i in 0..redundancy {
                let (cx, cy) = ((3 + i) % 8, (4 + i) % 8);
                let val = block_r[cy][cx].round() as i32;
                votes[(val & 1) as usize] += 1;
            }
            bits.push(if votes[1] > votes[0] {1} else {0});
            bit_index += 1;
            if let Some(ref bar) = pb { bar.inc(1); }
            if bit_index >= bits_len { break; }
        }
        if bit_index >= bits_len { break; }
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

fn mask_image(img: &mut RgbaImage, level: StealthLevel, password: &str) {
    let mut rng = StdRng::seed_from_u64(u64::from_le_bytes(Sha256::digest(password.as_bytes())[..8].try_into().unwrap()));
    match level {
        StealthLevel::Low => mask_low(img, &mut rng),
        StealthLevel::Medium => mask_medium(img, &mut rng),
        StealthLevel::High => mask_high(img, &mut rng),
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Embed { cover, secret, output, password, redundancy, domain, stealth, progress } => {
            let cover_img = image::open(&cover).expect("Failed to open cover image");
            let mut secret_file = File::open(&secret).expect("Failed to open secret file");
            let mut content = Vec::new();
            secret_file.read_to_end(&mut content).unwrap();

            let compressed = bz2_compress(&content);
            let raw_bits = bytes_to_bits(&compressed);
            let final_bits = add_crc_and_len(&raw_bits);

            let key = generate_bits_fast(final_bits.len(), &password);
            let masked_bits = xor_bits(&final_bits, &key);

            let mut stego_img = match domain {
                Domain::Lsb => adaptive_embed_lsb(&cover_img, &masked_bits, &password, redundancy, progress),
                Domain::LsbMatch => adaptive_embed_lsb_match(&cover_img, &masked_bits, &password, redundancy, progress),
                Domain::Dct => dct_embed(&cover_img, &masked_bits, &password, redundancy, progress),
            };

            mask_image(&mut stego_img, stealth, &password);
            stego_img.save(&output).unwrap();
        },
        Commands::Extract { stego, output, password, redundancy, domain, progress } => {
            let stego_loaded = image::open(&stego).expect("Failed to open stego image");
            let bits_len;
            {
                let mut secret_file = File::open(&stego).unwrap();
                secret_file.read_to_end(&mut Vec::new()).unwrap();
            }
            // We don't know length yet; we will extract as many bits as image capacity
            let capacity = match domain {
                Domain::Lsb | Domain::LsbMatch => stego_loaded.to_rgba8().as_flat_samples().samples.len() / redundancy,
                Domain::Dct => {
                    let (w,h) = stego_loaded.dimensions();
                    ((w/8)*(h/8)) as usize
                }
            };
            bits_len = capacity;

            let extracted_bits = match domain {
                Domain::Lsb => adaptive_extract_lsb(&stego_loaded, bits_len, &password, redundancy, progress),
                Domain::LsbMatch => adaptive_extract_lsb(&stego_loaded, bits_len, &password, redundancy, progress),
                Domain::Dct => dct_extract(&stego_loaded, bits_len, &password, redundancy, progress),
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
    }
}

