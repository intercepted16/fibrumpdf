package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/pymupdf4llm-c/go/internal/extractor"
	"github.com/pymupdf4llm-c/go/internal/logger"
	rawdata "github.com/pymupdf4llm-c/go/internal/raw"
)

var Logger = logger.GetLogger("tojson")

//export pdf_to_json
func pdf_to_json(pdf_path *C.char, output_file *C.char) C.int {
	pdfPath, outputFile := C.GoString(pdf_path), C.GoString(output_file)
	err := pdfToJson(pdfPath, outputFile)
	if err == nil {
		return 0
	}
	return -1
}

func processPage(pageFile string) ([]byte, error) {
	rawData, err := rawdata.ReadRawPage(pageFile)
	if err != nil {
		return nil, err
	}
	page := extractor.ExtractPageFromRaw(rawData)
	pageJSON, err := json.Marshal(page)
	if err != nil {
		return nil, err
	}
	return pageJSON, nil
}

func pdfToJson(pdfPath, outputPath string) error {
	startTotal := time.Now()
	startRaw := time.Now()

	Logger.Info("beginning conversion...")
	Logger.Debug("paths", "pdf", pdfPath, "output", outputPath)

	tempRawDir, err := rawdata.ExtractAllPagesRaw(pdfPath)
	rawElapsed := time.Since(startRaw)
	if err != nil {
		Logger.Error("extraction error", "err", err)
		return err
	}
	defer os.RemoveAll(tempRawDir)

	entries, err := os.ReadDir(tempRawDir)
	if err != nil {
		Logger.Error("readdir error", "err", err)
		return err
	}
	var pageFiles []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "page_") && strings.HasSuffix(e.Name(), ".raw") {
			pageFiles = append(pageFiles, filepath.Join(tempRawDir, e.Name()))
		}
	}
	sort.Slice(pageFiles, func(i, j int) bool { return extractPageNum(pageFiles[i]) < extractPageNum(pageFiles[j]) })

	type pageResult struct {
		idx     int
		pageNum int
		json    []byte
		err     error
	}
	numWorkers := runtime.NumCPU()
	if numWorkers > len(pageFiles) {
		numWorkers = len(pageFiles)
	}
	targetWorkers := (len(pageFiles) + 2) / 3
	if len(pageFiles) >= 2 && targetWorkers < 2 {
		targetWorkers = 2
	}
	if targetWorkers > 0 && targetWorkers < numWorkers {
		numWorkers = targetWorkers
	}
	if len(pageFiles) < 64 && numWorkers > 8 {
		numWorkers = 8
	}
	threshold := 2
	outputDir := filepath.Dir(outputPath)
	tempFile, err := os.CreateTemp(outputDir, "tojson-*.tmp")
	if err != nil {
		Logger.Error("output file error", "err", err)
		return err
	}
	tempPath := tempFile.Name()
	cleanupTemp := true
	defer func() {
		if tempFile != nil {
			tempFile.Close()
		}
		if cleanupTemp {
			os.Remove(tempPath)
		}
	}()
	writer := bufio.NewWriter(tempFile)
	if _, err := writer.WriteString("["); err != nil {
		Logger.Error("write error", "err", err)
		return err
	}

	wroteAny := false
	writePage := func(pageJSON []byte, pageNum int) error {
		if wroteAny {
			if _, err := writer.WriteString(","); err != nil {
				return err
			}
		}
		if _, err := writer.Write(pageJSON); err != nil {
			return err
		}
		wroteAny = true
		Logger.Debug("wrote page", "page", pageNum)
		return nil
	}

	if len(pageFiles) < threshold {
		for _, pageFile := range pageFiles {
			pageNum := extractPageNum(pageFile)
			pageJSON, err := processPage(pageFile)
			if err != nil {
				Logger.Error("processing error", "err", err)
				return err
			}
			if err := writePage(pageJSON, pageNum); err != nil {
				Logger.Error("write error", "err", err)
				return err
			}
		}
	} else {
		var wg sync.WaitGroup
		pageChan := make(chan int, numWorkers)
		resultChan := make(chan pageResult, numWorkers)

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range pageChan {
					pageFile := pageFiles[idx]
					pageNum := extractPageNum(pageFile)
					pageJSON, err := processPage(pageFile)
					resultChan <- pageResult{idx: idx, pageNum: pageNum, json: pageJSON, err: err}
					Logger.Debug("processed page", "page", pageNum, "err", err)
				}
			}()
		}

		go func() {
			wg.Wait()
			close(resultChan)
		}()

		go func() {
			for i := range pageFiles {
				pageChan <- i
			}
			close(pageChan)
		}()

		pending := make(map[int]pageResult, numWorkers)
		nextIdx := 0
		var firstErr error
		for res := range resultChan {
			if res.err != nil && firstErr == nil {
				firstErr = res.err
				Logger.Error("processing error", "err", res.err)
			}
			pending[res.idx] = res
			for {
				nextRes, ok := pending[nextIdx]
				if !ok {
					break
				}
				if firstErr == nil {
					if err := writePage(nextRes.json, nextRes.pageNum); err != nil {
						firstErr = err
						Logger.Error("write error", "err", err)
					}
				}
				delete(pending, nextIdx)
				nextIdx++
			}
		}
		if firstErr != nil {
			return firstErr
		}
	}

	if _, err := writer.WriteString("]\n"); err != nil {
		Logger.Error("write error", "err", err)
		return err
	}
	if err := writer.Flush(); err != nil {
		Logger.Error("write error", "err", err)
		return err
	}
	if err := tempFile.Close(); err != nil {
		Logger.Error("output file error", "err", err)
		return err
	}
	tempFile = nil
	if err := os.Rename(tempPath, outputPath); err != nil {
		Logger.Error("rename error", "err", err)
		return err
	}
	cleanupTemp = false

	totalElapsed := time.Since(startTotal)
	Logger.Info("raw data extraction", "timeInC", rawElapsed)
	Logger.Info("high level data extraction", "timeInGo", (totalElapsed - rawElapsed))
	Logger.Info("total conversion time", "totalTime", totalElapsed)

	Logger.Info("success")
	return nil
}

//export free_string
func free_string(s *C.char) { C.free(unsafe.Pointer(s)) }

func extractPageNum(filename string) int {
	base := filepath.Base(filename)
	base = strings.TrimPrefix(base, "page_")
	base = strings.TrimSuffix(base, ".raw")
	base = strings.TrimSuffix(base, ".json")
	num, _ := strconv.Atoi(base)
	return num
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./tojson <input.pdf> [output_json]")
		os.Exit(1)
	}
	err := pdfToJson(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
