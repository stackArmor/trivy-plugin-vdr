package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRunK8sPassesPullSecretAuthsToRegistryBuild(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runK8s" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Build" {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "registry" {
				return true
			}
			if len(call.Args) < 3 {
				return true
			}
			if ident, ok := call.Args[2].(*ast.Ident); ok && ident.Name == "secretAuths" {
				found = true
			}
			return true
		})
		return false
	})

	if !found {
		t.Fatal("runK8s does not pass secretAuths to registry.Build")
	}
}
