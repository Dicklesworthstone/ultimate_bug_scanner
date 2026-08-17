// GH #96 regression fixture: loop-allocation must not fire through trait
// impls, cold error-path closures, or async blocks, and the path-join
// heuristic must not fire on Vec::push of path-named variables.
use std::path::PathBuf;

pub struct Todo {
    items: Vec<String>,
}

pub trait Describe {
    fn describe(&self) -> String;
}

// `impl Trait for Type {` is not a loop header; allocations in loop-free
// methods inside a trait impl must stay quiet.
impl Describe for Todo {
    fn describe(&self) -> String {
        format!("todo with {} items", self.items.len())
    }
}

impl Todo {
    // Loop-free async fn: map_err/ok_or_else closures are cold error branches.
    pub async fn execute(&self, raw: &str) -> Result<String, String> {
        let parsed: usize = raw
            .trim()
            .parse()
            .map_err(|e| format!("invalid index: {e}"))?;
        let entry = self
            .items
            .get(parsed)
            .ok_or_else(|| "missing entry".to_string())?;
        Ok(entry.to_owned())
    }
}

// Genuine loop, but the only allocation sits in a cold map_err closure that
// runs on the failure branch, not per iteration.
pub fn read_all(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for p in paths {
        let text = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
        out.push(text);
    }
    Ok(out)
}

// Genuine loop with an async block: the allocation is deferred work inside the
// spawned future, not a per-iteration hot-path allocation.
pub fn spawn_all(names: Vec<&'static str>) {
    for name in names {
        std::mem::drop(async move { format!("task {name}") });
    }
}

// Vec::push of a variable *named* path is a collection append, not a
// filesystem join.
pub fn path_like_inputs(args: &[String]) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        let path = PathBuf::from(arg);
        paths.push(path);
    }
    paths
}
