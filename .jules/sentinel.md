## 2026-11-05 - Path Traversal Protection in Review Rule Source Loading
**Vulnerability:** Review rules reading source files from the working tree directly joined paths using `path.Join` without ensuring the paths stayed within the repository root, allowing directory traversal (e.g., `../secret`).
**Learning:** `path.Join` operates on POSIX path semantics and does not sanitize directory traversal elements across OS boundaries or enforce locality; Go's `filepath.IsLocal` and `filepath.Join` should always be paired to validate relative paths before accessing the filesystem or invoking git commands on index entries.
**Prevention:** Always validate `!filepath.IsLocal(path) || path == "."` before reading source contents in any rule inspector or analyzer.
