package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"bufio"
	"bytes"
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

	"github.com/fibrumpdf/go/internal/extractor"
	"github.com/fibrumpdf/go/internal/logger"
	rawdata "github.com/fibrumpdf/go/internal/raw"
)

var Logger = logger.GetLogger("tomd")

var bufferPool = sync.Pool{
	New: func() any {
		b := new(bytes.Buffer)
		b.Grow(4096)
		return b
	},
}

//export pdf_to_json
func pdf_to_json(pdf_path *C.char, output_file *C.char) C.int {
	pdfPath, outputFile := C.GoString(pdf_path), C.GoString(output_file)
	err := pdfToJson(pdfPath, outputFile)
	if err == nil {
		return 0
	}
	return -1
}

func readRawPageData(pageFile string) (*rawdata.PageData, error) {
	return rawdata.ReadRawPage(pageFile)
}

func processRawPage(rawData *rawdata.PageData, buf *bytes.Buffer) error {
	page := extractor.ExtractPageFromRaw(rawData)
	buf.Reset()
	encoder := json.NewEncoder(buf)
	if err := encoder.Encode(page); err != nil {
		return err
	}
	return nil
}

func pdfToJson(pdfPath, outputPath string) error {
	startTotal := time.Now()
	startRaw := time.Now()

	Logger.Info("beginning conversion...")
	Logger.Debug("paths", "pdf", pdfPath, "output", outputPath)

	tempRawDir, err := bridge.ExtractAllPagesRaw(pdfPath)
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
		pageNum int
		json    []byte
		err     error
	}
	var results []pageResult
	numWorkers := runtime.NumCPU()
	threshold := 10
	if numWorkers*2 > threshold {
		threshold = numWorkers * 2
	}
	if len(pageFiles) < threshold {
		// sequential
		results = make([]pageResult, len(pageFiles))
		for i, pageFile := range pageFiles {
			pageNum := extractPageNum(pageFile)
			rawData, err := readRawPageData(pageFile)
			if err != nil {
				Logger.Error("processing error", "err", err)
				return err
			}
			buf := bufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			err = processRawPage(rawData, buf)
			if err != nil {
				bufferPool.Put(buf)
				Logger.Error("processing error", "err", err)
				return err
			}
			result := buf.Bytes()
			if len(result) > 0 && result[len(result)-1] == '\n' {
				result = result[:len(result)-1]
			}
			pageJSON := append([]byte(nil), result...)
			buf.Reset()
			bufferPool.Put(buf)
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
					rawData, err := readRawPageData(pageFile)
					if err != nil {
						resultChan <- pageResult{idx: idx, pageNum: pageNum, json: nil, err: err}
						Logger.Debug("processed page", "page", pageNum, "err", err)
						continue
					}
					buf := bufferPool.Get().(*bytes.Buffer)
					buf.Reset()
					err = processRawPage(rawData, buf)
					if err != nil {
						bufferPool.Put(buf)
						resultChan <- pageResult{idx: idx, pageNum: pageNum, json: nil, err: err}
						Logger.Debug("processed page", "page", pageNum, "err", err)
						continue
					}
					result := buf.Bytes()
					if len(result) > 0 && result[len(result)-1] == '\n' {
						result = result[:len(result)-1]
					}
					output := append([]byte(nil), result...)
					buf.Reset()
					bufferPool.Put(buf)
					resultChan <- pageResult{idx: idx, pageNum: pageNum, json: output, err: nil}
					Logger.Debug("processed page", "page", pageNum)
				}
			}()
		}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range pageChan {
				pageFile := pageFiles[idx]
				pageNum := extractPageNum(pageFile)
				pageJSON, err := processPage(pageFile)
				results[idx] = pageResult{pageNum: pageNum, json: pageJSON, err: err}
				Logger.Debug("processed page", "page", pageNum, "err", err)
			}
		}()
	}

	for i := range pageFiles {
		pageChan <- i
	}
	close(pageChan)
	wg.Wait()

}

	for _, res := range results {
		if res.err != nil {
			Logger.Error("processing error", "err", res.err)
			return res.err
		}
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		Logger.Error("output file error", "err", err)
		return err
	}
	defer outFile.Close()

	pageList := make([]json.RawMessage, len(results))
	for i, res := range results {
		pageList[i] = json.RawMessage(res.json)
		Logger.Debug("wrote page", "page", res.pageNum)
	}

	encoder := json.NewEncoder(outFile)
	if err := encoder.Encode(pageList); err != nil {
		Logger.Error("write error", "err", err)
		return err
	}

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
	pdfToJson(os.Args[1], os.Args[2])
}
