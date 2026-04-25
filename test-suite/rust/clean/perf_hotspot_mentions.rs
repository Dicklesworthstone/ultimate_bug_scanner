fn documentation_mentions_only() -> &'static str {
    r#"
    Performance notes:
    for item in items { let _ = Regex::new(pattern); }
    text.chars().nth(index)
    for item in items { format!("item:{item}"); }
    "#
}

fn cached_lookup(input: &str, offsets: &[usize]) -> Vec<Option<char>> {
    let chars: Vec<char> = input.chars().collect();
    offsets.get(0).map(|_| ()).into_iter().flat_map(|_| {
        offsets.iter().map(|offset| chars.get(*offset).copied())
    }).collect()
}

fn append_labels(items: &[&str]) -> Vec<String> {
    let mut labels = Vec::with_capacity(items.len());
    let mut scratch = String::new();
    for item in items {
        scratch.clear();
        scratch.push_str("item:");
        scratch.push_str(item);
        labels.push(scratch.clone());
    }
    labels
}

fn notes() {
    // loop { let _ = regex::Regex::new(".*"); } is documentation only.
    let _ = documentation_mentions_only();
}
