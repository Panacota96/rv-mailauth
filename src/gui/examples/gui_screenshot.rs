//! Renders the window headless (no display, no GPU) to PNG files, for the documentation:
//!
//!     cargo run -p rv-mailauth-gui --example gui_screenshot -- docs/images [en|es|fr]
//!
//! It analyses `examples/sample/evidence` from GUI settings (key file `examples/sample/dkim-keys.txt`, own
//! domain example.org), reads the run back from its audit log and writes:
//! - `gui-main.png`: the main window after the finished run (options, results table);
//! - `gui-message.png`: the message viewer on `03-body-edited.eml` (digest-checked outputs).
//!
//! egui's tessellated meshes are rasterised on the CPU (textured triangles, premultiplied alpha), so the
//! picture is what the window draws, minus the GPU.
#![forbid(unsafe_code)]

use eframe::egui;
use egui::epaint::{ClippedPrimitive, Color32, ImageData, Primitive, TextureId};
use rv_mailauth_core::model::Isolation;
use rv_mailauth_gui::app::HashInvApp;
use rv_mailauth_gui::state::{GuiState, OptionChange};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

struct Tex {
    w: usize,
    h: usize,
    px: Vec<Color32>,
}

impl Tex {
    /// Bilinear sample of premultiplied texels, clamped at the edges.
    fn sample(&self, u: f32, v: f32) -> [f32; 4] {
        let x = (u * self.w as f32 - 0.5).clamp(0.0, (self.w - 1) as f32);
        let y = (v * self.h as f32 - 0.5).clamp(0.0, (self.h - 1) as f32);
        let (x0, y0) = (x.floor() as usize, y.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(self.w - 1), (y0 + 1).min(self.h - 1));
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let at = |x: usize, y: usize| {
            let c = self.px[y * self.w + x];
            [c.r() as f32, c.g() as f32, c.b() as f32, c.a() as f32]
        };
        let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
        let mut o = [0.0; 4];
        for i in 0..4 {
            let top = a[i] + (b[i] - a[i]) * fx;
            let bot = c[i] + (d[i] - c[i]) * fx;
            o[i] = (top + (bot - top) * fy) / 255.0;
        }
        o
    }
}

fn rasterise(
    prims: &[ClippedPrimitive],
    textures: &HashMap<TextureId, Tex>,
    ppp: f32,
    (width, height): (usize, usize),
) -> Vec<[f32; 4]> {
    let mut canvas = vec![[0.0f32, 0.0, 0.0, 1.0]; width * height];
    for p in prims {
        let Primitive::Mesh(mesh) = &p.primitive else {
            continue;
        };
        let Some(tex) = textures.get(&mesh.texture_id) else {
            continue;
        };
        let cx0 = (p.clip_rect.min.x * ppp).max(0.0).floor() as i64;
        let cy0 = (p.clip_rect.min.y * ppp).max(0.0).floor() as i64;
        let cx1 = ((p.clip_rect.max.x * ppp).ceil() as i64).min(width as i64);
        let cy1 = ((p.clip_rect.max.y * ppp).ceil() as i64).min(height as i64);
        for t in mesh.indices.as_chunks::<3>().0 {
            let v = [
                &mesh.vertices[t[0] as usize],
                &mesh.vertices[t[1] as usize],
                &mesh.vertices[t[2] as usize],
            ];
            let pt: Vec<[f32; 2]> = v.iter().map(|v| [v.pos.x * ppp, v.pos.y * ppp]).collect();
            let area = (pt[1][0] - pt[0][0]) * (pt[2][1] - pt[0][1])
                - (pt[2][0] - pt[0][0]) * (pt[1][1] - pt[0][1]);
            if area.abs() < 1e-9 {
                continue;
            }
            let minx = pt.iter().map(|p| p[0]).fold(f32::MAX, f32::min).floor() as i64;
            let maxx = pt.iter().map(|p| p[0]).fold(f32::MIN, f32::max).ceil() as i64;
            let miny = pt.iter().map(|p| p[1]).fold(f32::MAX, f32::min).floor() as i64;
            let maxy = pt.iter().map(|p| p[1]).fold(f32::MIN, f32::max).ceil() as i64;
            for y in miny.max(cy0)..maxy.min(cy1) {
                for x in minx.max(cx0)..maxx.min(cx1) {
                    let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
                    let e = |a: [f32; 2], b: [f32; 2]| {
                        (b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0])
                    };
                    let w0 = e(pt[1], pt[2]) / area;
                    let w1 = e(pt[2], pt[0]) / area;
                    let w2 = e(pt[0], pt[1]) / area;
                    if w0 < 0.0 || w1 < 0.0 || w2 < 0.0 {
                        continue;
                    }
                    let u = w0 * v[0].uv.x + w1 * v[1].uv.x + w2 * v[2].uv.x;
                    let vv = w0 * v[0].uv.y + w1 * v[1].uv.y + w2 * v[2].uv.y;
                    let s = tex.sample(u, vv);
                    let col = |i: usize| {
                        let c = |v: &egui::epaint::Vertex| v.color.to_array()[i] as f32 / 255.0;
                        w0 * c(v[0]) + w1 * c(v[1]) + w2 * c(v[2])
                    };
                    let src = [s[0] * col(0), s[1] * col(1), s[2] * col(2), s[3] * col(3)];
                    let d = &mut canvas[y as usize * width + x as usize];
                    for i in 0..4 {
                        d[i] = src[i] + d[i] * (1.0 - src[3]);
                    }
                }
            }
        }
    }
    canvas
}

/// Runs a few frames of `app` at `size` and writes the picture to `target`.
fn render(app: &mut HashInvApp, size: (usize, usize), target: &Path) {
    let (w, h) = size;
    let ctx = egui::Context::default();
    // A fresh context per picture: the theme is applied by the app only once per window.
    rv_mailauth_gui::app::apply_theme(&ctx);
    let mut textures: HashMap<TextureId, Tex> = HashMap::new();
    let mut last = None;
    for frame in 0..4 {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(w as f32, h as f32),
            )),
            time: Some(frame as f64 * 0.1),
            ..Default::default()
        };
        let mut output = ctx.run_ui(raw, |ui| app.draw(ui));
        for (id, deltas) in &output.textures_delta.set {
            for d in deltas {
                let ImageData::Color(img) = &d.image;
                match d.pos {
                    None => {
                        textures.insert(
                            *id,
                            Tex {
                                w: img.size[0],
                                h: img.size[1],
                                px: img.pixels.clone(),
                            },
                        );
                    }
                    Some([x0, y0]) => {
                        let t = textures.get_mut(id).expect("patch of a known texture");
                        for y in 0..img.size[1] {
                            for x in 0..img.size[0] {
                                t.px[(y0 + y) * t.w + x0 + x] = img.pixels[y * img.size[0] + x];
                            }
                        }
                    }
                }
            }
        }
        // Applied above (this renderer keeps every texture until the end).
        output.textures_delta.clear();
        last = Some(output);
    }
    let output = last.expect("frames ran");
    let ppp = output.pixels_per_point;
    let prims = ctx.tessellate(output.shapes, ppp);
    let canvas = rasterise(&prims, &textures, ppp, size);
    let rgba: Vec<u8> = canvas
        .iter()
        .flat_map(|p| {
            let a = p[3].clamp(1e-6, 1.0);
            [p[0] / a, p[1] / a, p[2] / a, 1.0].map(|c| (c.clamp(0.0, 1.0) * 255.0).round() as u8)
        })
        .collect();
    let file = std::fs::File::create(target).expect("create png");
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()
        .expect("png")
        .write_image_data(&rgba)
        .expect("png data");
    println!(
        "wrote {} ({w}x{h}, {} meshes)",
        target.display(),
        prims.len()
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
    let ui_lang = args.next().unwrap_or_else(|| "en".into());
    std::fs::create_dir_all(&dir).expect("output folder");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // A short fixed name: the paths appear in the window (no user name in the documentation).
    let out = std::env::temp_dir().join("rv-mailauth-shot");
    let _ = std::fs::remove_dir_all(&out);

    let mut s = GuiState {
        timestamp: false,
        actor: "Examiner".into(),
        case_id: "DEMO-001".into(),
        ..Default::default()
    };
    s.add_input(root.join("examples/sample/evidence"));
    // Two algorithms, as the GUI contract shows (the other checkboxes are then disabled).
    s.toggle_algo(rv_mailauth_core::HashAlgo::Blake3)
        .expect("second algorithm");
    s.set_option(OptionChange::DkimKeys(
        root.join("examples/sample/dkim-keys.txt")
            .canonicalize()
            .expect("key file")
            .display()
            .to_string(),
    ))
    .expect("key file option");
    s.set_option(OptionChange::AddOwnDomain("example.org".into()))
        .expect("own domain");
    s.out_dir = out.display().to_string();
    let mut cfg = s.to_config().expect("config");
    // This example binary is not a registered worker executable: analyse in process (same code path).
    cfg.domain.isolation = Isolation::InProcess;
    s.start();
    let cancel = std::sync::atomic::AtomicBool::new(false);
    rv_mailauth_core::run(&cfg, &mut |e| s.apply(e), &cancel).expect("run");
    s.load_results();
    s.set_ui_lang(&ui_lang);
    // Show the options as the examiner set them (the GUI shows evidence paths relative to nothing else).
    s.inputs = vec![PathBuf::from(r"examples\sample\evidence")];
    s.options.dkim_keys = Some(PathBuf::from(r"examples\sample\dkim-keys.txt"));
    s.out_dir = "rakvor-out".into();
    let mut app = HashInvApp::from_state(s);
    render(&mut app, (1400, 1560), &dir.join("gui-main.png"));

    let body = app
        .state()
        .run_view
        .as_ref()
        .and_then(|r| r.rows.iter().position(|x| x.name == "03-body-edited.eml"))
        .expect("body-edited sample in the results");
    assert!(app.state_mut().open_message(body), "viewer opens");
    render(&mut app, (1500, 1000), &dir.join("gui-message.png"));
    let _ = std::fs::remove_dir_all(&out);
}
