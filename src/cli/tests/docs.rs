//! The quick guide (docs/quick-guide{,.es,.fr}.md) covers what the binary offers: every documented subcommand,
//! every long flag of the six common tasks (in that task's own section), every GUI button, tick box and radio
//! button (by its full label in i18n/<lang>.json, read from src/gui/src/app.rs) and every exit code, in all three
//! languages. The Spanish and French guides keep the shape of the English one. Facts come from the binary itself
//! (`docs-cli`, `--help`, `describe --json`) and from the GUI source, so a new command, flag, button or exit code
//! fails this test until the guide documents it.
//!
//! Not scanned: the selectors drawn with `egui::ComboBox` and `selectable_label` (interface and report language,
//! custody form, mbox variant, clock skew and worker-limit presets); the guide names them in its prose and its
//! table.

use assert_cmd::Command;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const TOOL: &str = "rv-mailauth";
/// The (sub)commands behind the six common tasks, with the task sections ("## Task <N>: …") that document their
/// flags: 1 analyze, 2 analyze in a case folder, 3 verify-log, 4 verify-case, 5 timestamp after offline work,
/// 6 DKIM key files (keys import, keys show).
const TASK_COMMANDS: &[(&str, &[u32])] = &[
    ("analyze", &[1, 2]),
    ("verify-log", &[3]),
    ("verify-case", &[4]),
    ("timestamp", &[5]),
    ("keys import", &[6]),
    ("keys show", &[6]),
];
const TASKS: &[u32] = &[1, 2, 3, 4, 5, 6];
/// GUI controls whose label is not an i18n string by design, each matched as the exact call: the hash
/// algorithm tick boxes show the algorithm names (md5, sha256, …) as they are.
const UNTRANSLATED_LABELS: &[&str] = &["egui::Checkbox::new(&mut on, a.name())"];
const LANGS: &[&str] = &["en", "es", "fr"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{}: {}", rel, e))
}

fn guide(lang: &str) -> String {
    match lang {
        "en" => read("docs/quick-guide.md"),
        l => read(&format!("docs/quick-guide.{}.md", l)),
    }
}

fn run(args: &[&str]) -> String {
    let out = Command::cargo_bin(TOOL)
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{:?}: {:?}", args, out);
    String::from_utf8(out.stdout).unwrap()
}

/// `--help` of a (possibly nested) subcommand.
fn help(command: &str) -> String {
    let mut args: Vec<&str> = command.split(' ').collect();
    args.push("--help");
    run(&args)
}

/// The subcommands documented in usage-cli.md, read from the generator (`## rv-mailauth <name>` headings, nested
/// ones as `## rv-mailauth keys import`, or `### rv-mailauth <name> <child>`).
fn documented_commands() -> Vec<String> {
    let (top, nested) = (format!("## {} ", TOOL), format!("### {} ", TOOL));
    run(&["docs-cli"])
        .lines()
        .filter_map(|l| {
            l.strip_prefix(&top)
                .or_else(|| l.strip_prefix(&nested))
                .map(str::to_string)
        })
        .collect()
}

/// The long flags of a subcommand, from the option lines of its `--help` (`-i, --input <PATH>`, `--online`).
fn long_flags(command: &str) -> Vec<String> {
    help(command)
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            // Option lines are indented by 2 (`-i, --input`) or 6 (`--tsa-url`); their help text by 10.
            if l.len() - t.len() > 6 {
                return None;
            }
            let t = match t.as_bytes() {
                [b'-', c, b',', b' ', ..] if c.is_ascii_alphanumeric() => &t[4..],
                _ => t,
            };
            let flag = t.strip_prefix("--")?.split([' ', '=', '[']).next()?;
            let word = flag
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            (word && !flag.is_empty() && flag != "help" && flag != "version")
                .then(|| format!("--{}", flag))
        })
        .collect()
}

fn name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// True when `token` appears as a whole word: `--case` does not match inside `--case-dir`, and
/// `rv-mailauth verify` does not match inside `rv-mailauth verify-log`.
fn has_token(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + token.len()..].chars().next();
        !before.is_some_and(name_char) && !after.is_some_and(name_char)
    })
}

/// The text of each task section, by task number: a `## ` heading whose second word is the number
/// ("## Task 3: …", "## Tarea 3: …", "## Tâche 3 : …"), up to the next `## ` heading.
fn task_sections(text: &str) -> BTreeMap<u32, String> {
    let mut sections = BTreeMap::new();
    let mut current: Option<u32> = None;
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            current = h
                .split_whitespace()
                .nth(1)
                .map(|w| w.trim_end_matches(':'))
                .and_then(|w| w.parse().ok());
            continue;
        }
        if let Some(n) = current {
            let s: &mut String = sections.entry(n).or_default();
            s.push_str(line);
            s.push('\n');
        }
    }
    sections
}

/// The exit codes of every documented command: describe's table, plus each command's EXIT CODES section.
fn exit_codes() -> BTreeSet<String> {
    let v: serde_json::Value = serde_json::from_str(&run(&["describe", "--json"])).unwrap();
    let mut codes: BTreeSet<String> = v["exit_codes"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    for c in documented_commands() {
        let help = help(&c);
        let Some(section) = help.split("EXIT CODES:\n").nth(1) else {
            continue;
        };
        for line in section
            .lines()
            .take_while(|l| l.is_empty() || l.starts_with(' '))
        {
            if let Some(code) = line.split_whitespace().next()
                && line.starts_with("  ")
                && !line.starts_with("   ")
                && code.chars().all(|c| c.is_ascii_digit())
            {
                codes.insert(code.to_string());
            }
        }
    }
    codes
}

/// The label of a GUI control as the window shows it, ellipsis included ("Add files…").
fn ui_label(lang: &str, key: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(&read(&format!("i18n/{}.json", lang))).unwrap();
    v["ui"][key]
        .as_str()
        .unwrap_or_else(|| panic!("i18n/{}.json has no ui.{}", lang, key))
        .to_string()
}

/// True when the guide names the whole label in bold: `**Add files…**`, `**Preview**`. A longer label that
/// only starts with it (`**Preview window**`) does not count.
fn names_label(text: &str, label: &str) -> bool {
    text.contains(&format!("**{}**", label))
}

/// The `tr("key")` keys in a piece of source, in order (a call whose name is exactly `tr`, so `str("x")` does
/// not count).
fn tr_keys(src: &str) -> Vec<String> {
    src.match_indices("tr(\"")
        .filter(|(i, _)| !src[..*i].chars().next_back().is_some_and(name_char))
        .filter_map(|(i, p)| src[i + p.len()..].split('"').next().map(str::to_string))
        .collect()
}

/// Label variables bound to translated strings: `let l_x = tr("k");` and
/// `let (l_a, l_b) = (tr("ka"), tr("kb"));` (also over several lines).
fn label_bindings(app: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for part in app.split("let ").skip(1) {
        let Some((lhs, rhs)) = part.split_once(" = ") else {
            continue;
        };
        let rhs = rhs.split(";").next().unwrap_or("");
        let names: Vec<String> = lhs
            .trim_matches(|c| c == '(' || c == ')')
            .split(',')
            .map(|n| n.trim().to_string())
            .collect();
        let keys = tr_keys(rhs);
        if !keys.is_empty() && names.len() == keys.len() {
            for (n, k) in names.into_iter().zip(keys) {
                vars.insert(n, k);
            }
        }
    }
    vars
}

/// A control's label: an i18n key, or a literal string (trimmed: `" + "` is the button **+**).
#[derive(Debug, PartialEq)]
enum Label {
    Key(String),
    Literal(String),
}

/// The calls that draw a button, a tick box or a radio button. `radio_value(&mut v, x, label)` and
/// `selectable_value(&mut v, x, label)` take their label last.
const CONTROLS: &[&str] = &[
    "button(",
    "checkbox(",
    "radio(",
    "radio_value(",
    "selectable_value(",
    "button::new(",
    "checkbox::new(",
];

/// The literal label passed straight to the control: `ui.small_button("x")`, `ui.button(" + ")`.
fn direct_literal(line: &str) -> Option<String> {
    ["button(\"", "radio(\""].iter().find_map(|p| {
        let rest = &line[line.find(p)? + p.len()..];
        let lit = rest.split('"').next()?.trim();
        (!lit.is_empty()).then(|| lit.to_string())
    })
}

/// The i18n keys behind a label built at run time, `tr(&format!("opt_{}", kind))`: every `ui` key of
/// i18n/en.json that starts with the literal prefix.
fn format_keys(line: &str) -> Vec<String> {
    let Some(prefix) = line
        .split("tr(&format!(\"")
        .nth(1)
        .and_then(|r| r.split(['{', '"']).next())
    else {
        return vec![];
    };
    let v: serde_json::Value = serde_json::from_str(&read("i18n/en.json")).unwrap();
    v["ui"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| k.starts_with(prefix))
        .cloned()
        .collect()
}

/// True when the parentheses opened on this line are not all closed on it (the call goes on to the next line).
fn call_continues(line: &str) -> bool {
    line.matches('(').count() > line.matches(')').count()
}

/// The source without whitespace, to compare a call written over several lines with a skip entry.
fn squash(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The label argument of `radio_value(&mut v, x, label)` / `selectable_value(&mut v, x, label)`: the last
/// argument of the call (which may go on over several lines, `span`).
fn value_label_arg(span: &str) -> Option<String> {
    let start = ["radio_value(", "selectable_value("]
        .iter()
        .find_map(|p| span.find(p).map(|i| i + p.len()))?;
    let (mut depth, mut in_str, mut prev) = (0i32, false, ' ');
    let (mut args, mut cur) = (Vec::<String>::new(), String::new());
    for ch in span[start..].chars() {
        if in_str {
            in_str = !(ch == '"' && prev != '\\');
            cur.push(ch);
        } else {
            match ch {
                '"' => {
                    in_str = true;
                    cur.push(ch);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    cur.push(ch);
                }
                ')' | ']' | '}' if depth == 0 => {
                    args.push(cur.trim().to_string());
                    return args.into_iter().rfind(|a| !a.is_empty());
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    cur.push(ch);
                }
                ',' if depth == 0 => args.push(std::mem::take(&mut cur).trim().to_string()),
                c => cur.push(c),
            }
        }
        prev = ch;
    }
    None
}

/// Every button, tick box and radio button drawn by the GUI, resolved to its label: first from the control's own
/// line (a literal passed straight to it, a `tr("…")` key, a key built with `format!`, a label variable, the label
/// of an unlabelled tick box, another literal), then from the next lines (up to where the parentheses balance)
/// only when the call is not closed on this one. For `radio_value` and `selectable_value` the label is the last
/// argument of the call. A control whose label cannot be resolved fails the test, so a
/// new control always has to be documented (or listed in UNTRANSLATED_LABELS).
fn gui_controls() -> Vec<Label> {
    let app = read("src/gui/src/app.rs");
    let vars = label_bindings(&app);
    let lines: Vec<&str> = app.lines().collect();
    let var_key = |src: &str| {
        vars.iter()
            .find(|(n, _)| has_token(src, n))
            .map(|(_, k)| k.clone())
    };
    let literal = |src: &str| {
        src.split("(\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let mut controls = vec![];
    for (i, l) in lines.iter().enumerate() {
        let lower = l.to_ascii_lowercase();
        if l.trim_start().starts_with("//") || !CONTROLS.iter().any(|c| lower.contains(c)) {
            continue;
        }
        // A call that goes on over the next lines (`egui::Button::new(` / `RichText::new(tr("k"))`): its label is
        // in the lines up to where the parentheses balance (at most 6).
        let mut next = String::new();
        let mut span = l.to_string();
        for more in lines.iter().skip(i + 1).take(6) {
            if !call_continues(&span) {
                break;
            }
            span.push(' ');
            span.push_str(more);
            next.push(' ');
            next.push_str(more);
        }
        if UNTRANSLATED_LABELS
            .iter()
            .any(|u| squash(&span).contains(&squash(u)))
        {
            continue;
        }
        if lower.contains("radio_value(") || lower.contains("selectable_value(") {
            // The label is the last argument: a literal, a `tr("…")` key or a label variable.
            let arg = value_label_arg(&span).unwrap_or_default();
            let label = if let Some(lit) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) {
                Label::Literal(lit.trim().to_string())
            } else if let Some(k) = tr_keys(&arg).into_iter().next().or_else(|| var_key(&arg)) {
                Label::Key(k)
            } else {
                panic!(
                    "app.rs:{}: cannot resolve the label `{}` of the GUI control `{}`: label it with tr(\"key\") \
                     or list the exact call in UNTRANSLATED_LABELS",
                    i + 1,
                    arg,
                    l.trim()
                );
            };
            controls.push(label);
            continue;
        }
        let built = format_keys(l);
        if !built.is_empty() {
            controls.extend(built.into_iter().map(Label::Key));
            continue;
        }
        let label = if let Some(lit) = direct_literal(l) {
            Label::Literal(lit)
        } else if let Some(k) = tr_keys(l).into_iter().next() {
            Label::Key(k)
        } else if let Some(k) = var_key(l) {
            Label::Key(k)
        } else if l.contains(", \"\")") {
            // An unlabelled tick box: its label is the `ui.label(..)` drawn just before it in the same row.
            let k = lines[i.saturating_sub(6)..i]
                .iter()
                .rev()
                .filter(|p| p.contains("ui.label("))
                .find_map(|p| var_key(p).or_else(|| tr_keys(p).into_iter().next()));
            Label::Key(k.unwrap_or_else(|| {
                panic!(
                    "app.rs:{}: cannot resolve the label of `{}`",
                    i + 1,
                    l.trim()
                )
            }))
        } else if let Some(lit) = literal(l) {
            Label::Literal(lit)
        } else if let Some(k) = call_continues(l)
            .then(|| tr_keys(&next).into_iter().next().or_else(|| var_key(&next)))
            .flatten()
        {
            Label::Key(k)
        } else {
            panic!(
                "app.rs:{}: cannot resolve the label of the GUI control `{}`: label it with tr(\"key\") \
                 or extend gui_controls()",
                i + 1,
                l.trim()
            );
        };
        controls.push(label);
    }
    controls
}

#[test]
fn quick_guide_documents_every_command_flag_button_and_exit_code() {
    let commands = documented_commands();
    assert!(commands.len() >= 8, "{:?}", commands);
    for lang in LANGS {
        let text = guide(lang);
        for c in &commands {
            assert!(
                has_token(&text, &format!("{} {}", TOOL, c)),
                "the {} quick guide does not mention `{} {}`",
                lang,
                TOOL,
                c
            );
        }
        let sections = task_sections(&text);
        assert_eq!(
            sections.keys().copied().collect::<Vec<_>>(),
            TASKS,
            "the {} quick guide must have the six task sections",
            lang
        );
        let mut checked = 0;
        for (c, tasks) in TASK_COMMANDS {
            assert!(commands.iter().any(|d| d == c), "{} is not a subcommand", c);
            let own: String = tasks.iter().map(|n| sections[n].as_str()).collect();
            assert!(
                has_token(&own, &format!("{} {}", TOOL, c)),
                "the {} quick guide does not show `{} {}` in task {:?}",
                lang,
                TOOL,
                c,
                tasks
            );
            for f in long_flags(c) {
                assert!(
                    has_token(&own, &f),
                    "the {} quick guide does not document `{} {}` in task {:?}",
                    lang,
                    c,
                    f,
                    tasks
                );
                checked += 1;
            }
        }
        assert!(checked >= 40, "{} task flags checked", checked);
    }
    let codes = exit_codes();
    assert!(codes.contains("0") && codes.contains("130"), "{:?}", codes);
    for code in &codes {
        for lang in LANGS {
            assert!(
                guide(lang)
                    .lines()
                    .any(|l| l.starts_with(&format!("| {} |", code))),
                "the {} quick guide has no exit-code row `| {} |`",
                lang,
                code
            );
        }
    }
}

#[test]
fn quick_guide_describes_every_gui_button_and_tick_box() {
    let controls = gui_controls();
    assert!(
        controls.contains(&Label::Key("start".into()))
            && controls.contains(&Label::Key("tsa".into()))
            && controls.contains(&Label::Key("browse".into()))
            && controls.contains(&Label::Key("opt_reports_flagged".into()))
            && controls.contains(&Label::Key("open_message".into()))
            && controls.contains(&Label::Literal("x".into())),
        "{:?}",
        controls
    );
    for c in &controls {
        for lang in LANGS {
            let label = match c {
                Label::Key(k) => ui_label(lang, k),
                Label::Literal(s) => s.clone(),
            };
            assert!(
                names_label(&guide(lang), &label),
                "the {} quick guide does not describe the GUI control {:?} (**{}**)",
                lang,
                c,
                label
            );
        }
    }
}

#[test]
fn value_controls_take_their_last_argument_as_label() {
    assert_eq!(
        value_label_arg(r#"ui.selectable_value(&mut f.kind, Some(k.clone()), tr("any"));"#)
            .as_deref(),
        Some(r#"tr("any")"#)
    );
    assert_eq!(
        value_label_arg(r#"ui.radio_value(&mut v, Mode::A, "UTC" ) "#).as_deref(),
        Some(r#""UTC""#)
    );
    assert_eq!(
        value_label_arg(
            "ui.selectable_value( &mut s, Some(x), format!(\"\\u{2265} {}\", c(k)), );"
        )
        .as_deref(),
        Some("format!(\"\\u{2265} {}\", c(k))")
    );
    assert!(
        squash("ui.selectable_value(\n  &mut s,\n  Some(x),")
            .contains(&squash("ui.selectable_value(&mut s, Some(x),"))
    );
}

#[test]
fn label_check_needs_the_whole_label() {
    assert!(names_label("Press **Add files…** first.", "Add files…"));
    assert!(!names_label("Press **Add files…** first.", "Add files"));
    assert!(!names_label("Open **Open report folder**.", "Open report"));
    assert!(!names_label(
        "Open **Open report** (x).",
        "Open report folder"
    ));
}

/// Headings and numbered steps outside code blocks.
fn shape(text: &str) -> (usize, usize) {
    let (mut headings, mut steps, mut fenced) = (0, 0, false);
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let t = line.trim_start();
        let digits = t.chars().take_while(char::is_ascii_digit).count();
        if line.starts_with('#') && line.trim_start_matches('#').starts_with(' ') {
            headings += 1;
        } else if digits > 0 && t[digits..].starts_with(". ") {
            steps += 1;
        }
    }
    (headings, steps)
}

#[test]
fn translated_quick_guides_have_the_same_headings_and_steps() {
    let (headings, steps) = shape(&guide("en"));
    assert!(headings >= 9 && steps >= 12, "{} {}", headings, steps);
    for lang in ["es", "fr"] {
        assert_eq!(
            shape(&guide(lang)),
            (headings, steps),
            "docs/quick-guide.{}.md: (headings, numbered steps) differ from the English guide",
            lang
        );
    }
}
