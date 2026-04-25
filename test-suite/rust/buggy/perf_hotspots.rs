use regex::Regex;

fn compile_regex_per_item(inputs: &[&str]) -> usize {
    let mut matches = 0;
    for value in inputs {
        let pattern = Regex::new(r"^[a-z0-9_-]+$").unwrap();
        if pattern.is_match(value) {
            matches += 1;
        }
    }
    matches
}

fn compile_regex_in_loop(limit: usize) {
    let mut count = 0;
    while count < limit {
        let _ = regex::Regex::new(r"\d+").unwrap();
        count += 1;
    }
}

fn repeated_character_lookup(input: &str, offsets: &[usize]) -> Vec<Option<char>> {
    let mut found = Vec::new();
    for offset in offsets {
        found.push(input.chars().nth(*offset));
        found.push(input.chars().nth_back(*offset));
    }
    found
}

fn allocate_per_item(items: &[&str]) -> Vec<String> {
    let mut labels = Vec::new();
    for item in items {
        labels.push(format!("item:{item}"));
        labels.push(item.to_string());
        labels.push(String::from(*item));
    }
    labels
}
