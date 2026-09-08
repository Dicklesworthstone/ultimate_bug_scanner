package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type resourceKind string

const (
	kindContext  resourceKind = "context_cancel"
	kindTicker   resourceKind = "ticker_stop"
	kindTimer    resourceKind = "timer_stop"
	kindFile     resourceKind = "file_handle"
	kindDB       resourceKind = "db_handle"
	kindListener resourceKind = "listener_close"
	kindMutex    resourceKind = "mutex_lock"
)

type resource struct {
	name     string
	kind     resourceKind
	position token.Position
	released bool
}

type scope struct {
	byName map[string][]*resource
}

func newScope() *scope {
	return &scope{byName: make(map[string][]*resource)}
}

type analyzer struct {
	fset       *token.FileSet
	resources  []*resource
	scopeStack []*scope
}

func newAnalyzer(fset *token.FileSet) *analyzer {
	return &analyzer{
		fset:       fset,
		scopeStack: []*scope{newScope()}, // global scope
	}
}

func (a *analyzer) currentScope() *scope {
	return a.scopeStack[len(a.scopeStack)-1]
}

func (a *analyzer) pushScope() {
	a.scopeStack = append(a.scopeStack, newScope())
}

func (a *analyzer) popScope() {
	if len(a.scopeStack) > 1 {
		a.scopeStack = a.scopeStack[:len(a.scopeStack)-1]
	}
}

func (a *analyzer) add(name string, kind resourceKind, pos token.Position) {
	res := &resource{name: name, kind: kind, position: pos}
	a.resources = append(a.resources, res)
	if name != "" {
		s := a.currentScope()
		s.byName[name] = append(s.byName[name], res)
	}
}

func (a *analyzer) lookup(name string) []*resource {
	// Look up from innermost scope to outer
	for i := len(a.scopeStack) - 1; i >= 0; i-- {
		s := a.scopeStack[i]
		if entries, ok := s.byName[name]; ok {
			return entries
		}
	}
	return nil
}

func (a *analyzer) markReleased(name string, kinds ...resourceKind) {
	if name == "" {
		return
	}
	entries := a.lookup(name)
	// When a name is rebound (e.g., `f := os.Open(...); f = os.Open(...); f.Close()`),
	// the close applies to the most recent acquisition bound to that identifier.
	for i := len(entries) - 1; i >= 0; i-- {
		res := entries[i]
		if res.released {
			continue
		}
		if len(kinds) == 0 || containsKind(kinds, res.kind) {
			res.released = true
			return
		}
	}
}

func containsKind(kinds []resourceKind, target resourceKind) bool {
	for _, k := range kinds {
		if k == target {
			return true
		}
	}
	return false
}

// Visit implements ast.Visitor.
func (a *analyzer) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	// Scope-creating nodes: manual walk with push/pop
	case *ast.FuncDecl:
		a.pushScope()
		if n.Recv != nil {
			ast.Walk(a, n.Recv)
		}
		if n.Type != nil {
			ast.Walk(a, n.Type)
		}
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		a.popScope()
		return nil
	case *ast.FuncLit:
		a.pushScope()
		if n.Type != nil {
			ast.Walk(a, n.Type)
		}
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		a.popScope()
		return nil
	case *ast.BlockStmt:
		a.pushScope()
		for _, stmt := range n.List {
			ast.Walk(a, stmt)
		}
		a.popScope()
		return nil
	case *ast.IfStmt:
		a.pushScope()
		if n.Init != nil {
			ast.Walk(a, n.Init)
		}
		if n.Cond != nil {
			ast.Walk(a, n.Cond)
		}
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		if n.Else != nil {
			ast.Walk(a, n.Else)
		}
		a.popScope()
		return nil
	case *ast.ForStmt:
		a.pushScope()
		if n.Init != nil {
			ast.Walk(a, n.Init)
		}
		if n.Cond != nil {
			ast.Walk(a, n.Cond)
		}
		if n.Post != nil {
			ast.Walk(a, n.Post)
		}
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		a.popScope()
		return nil
	case *ast.RangeStmt:
		a.pushScope()
		if n.Key != nil {
			ast.Walk(a, n.Key)
		}
		if n.Value != nil {
			ast.Walk(a, n.Value)
		}
		if n.X != nil {
			ast.Walk(a, n.X)
		}
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		a.popScope()
		return nil
	case *ast.SwitchStmt:
		a.pushScope()
		if n.Init != nil {
			ast.Walk(a, n.Init)
		}
		if n.Tag != nil {
			ast.Walk(a, n.Tag)
		}
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		a.popScope()
		return nil
	case *ast.TypeSwitchStmt:
		a.pushScope()
		if n.Init != nil {
			ast.Walk(a, n.Init)
		}
		if n.Assign != nil {
			ast.Walk(a, n.Assign)
		}
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		a.popScope()
		return nil
	case *ast.SelectStmt:
		a.pushScope()
		if n.Body != nil {
			ast.Walk(a, n.Body)
		}
		a.popScope()
		return nil
	case *ast.CaseClause:
		a.pushScope()
		for _, expr := range n.List {
			ast.Walk(a, expr)
		}
		for _, stmt := range n.Body {
			ast.Walk(a, stmt)
		}
		a.popScope()
		return nil
	case *ast.CommClause:
		a.pushScope()
		if n.Comm != nil {
			ast.Walk(a, n.Comm)
		}
		for _, stmt := range n.Body {
			ast.Walk(a, stmt)
		}
		a.popScope()
		return nil

	// Logic nodes
	case *ast.AssignStmt:
		a.handleAssign(n)
		return a
	case *ast.CallExpr:
		a.handleCall(n)
		return a
	case *ast.ReturnStmt:
		a.handleReturn(n)
		return a
	}

	return a
}

func (a *analyzer) handleReturn(ret *ast.ReturnStmt) {
	for _, res := range ret.Results {
		if id, ok := res.(*ast.Ident); ok {
			a.markReleasedAllScopes(id.Name)
		}
	}
}

func (a *analyzer) markReleasedAllScopes(name string) {
	if name == "" {
		return
	}
	// Traverse all scopes
	for _, scope := range a.scopeStack {
		if entries, ok := scope.byName[name]; ok {
			for _, res := range entries {
				if !res.released {
					res.released = true
				}
			}
		}
	}
}

func (a *analyzer) handleAssign(assign *ast.AssignStmt) {
	if len(assign.Rhs) == 0 {
		return
	}

	if len(assign.Rhs) == 1 {
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return
		}
		kind := classifyCall(call)
		if kind == "" {
			return
		}
		names := collectNames(assign.Lhs)
		pos := a.fset.Position(assign.Pos())

		switch kind {
		case kindContext:
			if len(names) >= 2 {
				name := names[len(names)-1]
				if name == "_" {
					name = ""
				}
				a.add(name, kind, pos)
			} else {
				a.add("", kind, pos)
			}
		default:
			if len(names) > 0 {
				name := names[0]
				if name != "" && name != "_" {
					a.add(name, kind, pos)
				}
			}
		}
		return
	}

	if len(assign.Lhs) == len(assign.Rhs) {
		names := collectNames(assign.Lhs)
		for i, expr := range assign.Rhs {
			call, ok := expr.(*ast.CallExpr)
			if !ok {
				continue
			}
			kind := classifyCall(call)
			if kind == "" {
				continue
			}
			name := names[i]
			if name == "" || name == "_" {
				continue
			}
			if kind == kindTicker || kind == kindTimer {
				a.add(name, kind, a.fset.Position(assign.Pos()))
			}
		}
	}
}

func classifyCall(call *ast.CallExpr) resourceKind {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg := exprName(sel.X)
	fn := sel.Sel.Name
	switch {
	case pkg == "context" && (fn == "WithCancel" || fn == "WithTimeout" || fn == "WithDeadline"):
		return kindContext
	case pkg == "time" && fn == "NewTicker":
		return kindTicker
	case pkg == "time" && fn == "NewTimer":
		return kindTimer
	case pkg == "os" && (fn == "Open" || fn == "OpenFile" || fn == "Create" || fn == "CreateTemp"):
		return kindFile
	case pkg == "sql" && (fn == "Open" || fn == "OpenDB"):
		return kindDB
	case pkg == "net" && (fn == "Listen" || fn == "ListenPacket" || fn == "ListenIP" || fn == "ListenTCP" || fn == "ListenUDP" || fn == "ListenUnix"):
		return kindListener
	default:
		return ""
	}
}

func (a *analyzer) handleCall(call *ast.CallExpr) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := fun.Sel.Name
		base := exprName(fun.X)
		switch name {
		case "Lock":
			if base != "" {
				a.add(base, kindMutex, a.fset.Position(call.Pos()))
			}
		case "Stop":
			a.markReleased(base, kindTicker, kindTimer)
		case "Close":
			a.markReleased(base, kindFile, kindDB, kindListener)
		case "Unlock":
			a.markReleased(base, kindMutex)
		}
	case *ast.Ident:
		a.markReleased(fun.Name, kindContext)
	}
}

func exprName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		base := exprName(v.X)
		if base == "" {
			return v.Sel.Name
		}
		return base + "." + v.Sel.Name
	case *ast.StarExpr:
		return exprName(v.X)
	default:
		return ""
	}
}

func collectNames(exprs []ast.Expr) []string {
	names := make([]string, 0, len(exprs))
	for _, expr := range exprs {
		switch v := expr.(type) {
		case *ast.Ident:
			names = append(names, v.Name)
		case *ast.SelectorExpr:
			names = append(names, exprName(v))
		case *ast.StarExpr:
			names = append(names, exprName(v.X))
		default:
			names = append(names, "")
		}
	}
	return names
}

func analyzeFile(path, root string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	visitor := newAnalyzer(fset)
	ast.Walk(visitor, file)

	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	var issues []string
	for _, res := range visitor.resources {
		if res.released {
			continue
		}
		line := res.position.Line
		location := fmt.Sprintf("%s:%d", rel, line)
		message := formatMessage(res.kind, res.name)
		issues = append(issues, fmt.Sprintf("%s\t%s\t%s", location, res.kind, message))
	}
	return issues, nil
}

func formatMessage(kind resourceKind, name string) string {
	subject := name
	if subject == "" {
		subject = "resource"
	}
	switch kind {
	case kindContext:
		return "context.With* cancel function never invoked"
	case kindTicker:
		return fmt.Sprintf("Ticker %s missing Stop()", subject)
	case kindTimer:
		return fmt.Sprintf("Timer %s missing Stop()", subject)
	case kindFile:
		return fmt.Sprintf("File handle %s opened without Close()", subject)
	case kindDB:
		return fmt.Sprintf("DB handle %s opened without Close()", subject)
	case kindListener:
		return fmt.Sprintf("Listener %s opened without Close()", subject)
	case kindMutex:
		return fmt.Sprintf("Mutex %s locked without Unlock()", subject)
	default:
		return "Resource not released"
	}
}

var ignoreDirs = map[string]struct{}{
	".git":       {},
	"vendor":      {},
	"node_modules": {},
	"testdata":    {},
	"dist":        {},
	"build":       {},
	"bin":         {},
}

func loadUbcsIgnore(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, ".ubsignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read .ubsignore: %w", err)
	}
	var pats []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pats = append(pats, strings.TrimSuffix(line, "/"))
	}
	return pats, nil
}

func matchesAny(rel string, patterns []string) bool {
	for _, pat := range patterns {
		if strings.HasPrefix(rel, pat) || strings.Contains(rel, "/"+pat) || rel == pat {
			return true
		}
		if matched, _ := filepath.Match(pat, rel); matched {
			return true
		}
		if matched, _ := filepath.Match(pat, filepath.Base(rel)); matched {
			return true
		}
	}
	return false
}

func collectGoFiles(root string) ([]string, error) {
	ignores, _ := loadUbcsIgnore(root)
	files := []string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rErr := filepath.Rel(root, path)
		if rErr == nil && len(ignores) > 0 && matchesAny(rel, ignores) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if _, skip := ignoreDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func readFilesFrom(listPath, root string) ([]string, error) {
	data, err := os.ReadFile(listPath)
	if err != nil {
		return nil, err
	}
	var rawEntries []string
	if bytes.Contains(data, []byte{0}) {
		for _, b := range bytes.Split(data, []byte{0}) {
			if len(b) > 0 {
				rawEntries = append(rawEntries, string(b))
			}
		}
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				rawEntries = append(rawEntries, line)
			}
		}
	}
	var files []string
	for _, entry := range rawEntries {
		if !strings.HasSuffix(entry, ".go") {
			continue
		}
		full := entry
		if !filepath.IsAbs(full) {
			full = filepath.Join(root, entry)
		}
		if st, err := os.Stat(full); err == nil && !st.IsDir() {
			files = append(files, full)
		}
	}
	sort.Strings(files)
	return files, nil
}

func main() {
	filesFrom := flag.String("files-from", "", "path to file containing list of Go files")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: resource_lifecycle_go.go [options] <project_dir>")
		os.Exit(2)
	}
	root, err := filepath.Abs(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var files []string
	if *filesFrom != "" {
		files, err = readFilesFrom(*filesFrom, root)
	} else {
		files, err = collectGoFiles(root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var outputs []string
	for _, file := range files {
		issues, err := analyzeFile(file, root)
		if err != nil {
			continue
		}
		outputs = append(outputs, issues...)
	}
	if len(outputs) > 0 {
		fmt.Println(strings.Join(outputs, "\n"))
	}
}

