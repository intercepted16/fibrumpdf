package testutil

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pymupdf4llm-c/go/internal/raw"
)

var TestDataDir string

func init() {
	root := FindProjectRoot()
	if root != "" {
		TestDataDir = filepath.Join(root, "test_data", "pdfs")
	}
}

func FindProjectRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(cwd, ".root")); err == nil {
			return cwd
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			return ""
		}
		cwd = parent
	}
}

func ExtractRawFromTestData(pdfName string) (string, error) {
	if TestDataDir == "" {
		return "", fmt.Errorf("extractRaw: no TestDataDir")
	}
	pdfPath := filepath.Join(TestDataDir, pdfName)
	if _, err := os.Stat(pdfPath); err != nil {
		return "", err
	}

	tempDir, err := raw.ExtractAllPagesRaw(pdfPath)
	if err != nil {
		return "", err
	}
	return tempDir, nil
}
