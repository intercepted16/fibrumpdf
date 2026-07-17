package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteOrderedPagesHandlesEmptyDocument(t *testing.T) {
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	if err := writeOrderedPages(writer, nil); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "[]\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

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

func TestPDFToJSONRefusesToOverwriteInput(t *testing.T) {
	input := filepath.Join(t.TempDir(), "document.pdf")
	contents := []byte("%PDF-placeholder")
	if err := os.WriteFile(input, contents, 0644); err != nil {
		t.Fatal(err)
	}

	err := pdfToJson(input, input)
	if err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("pdfToJson error = %v, want same-file error", err)
	}
	got, readErr := os.ReadFile(input)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, contents) {
		t.Fatal("input was modified")
	}
}
