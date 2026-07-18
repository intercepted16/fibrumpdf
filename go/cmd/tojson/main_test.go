package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONDocumentPreservesExistingOutputOnFailure(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "result.json")
	if err := os.WriteFile(output, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	invalidPage := filepath.Join(directory, "page_1.raw")
	if err := os.WriteFile(invalidPage, []byte("not raw page data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := writeJSONDocument(output, []string{invalidPage}); err == nil {
		t.Fatal("writeJSONDocument succeeded with invalid page data")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "original"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".fibrum-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary outputs left behind: %v", matches)
	}
}
