package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

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
		pageNum int
		json    []byte
		err     error
		idx     int
	}

	type rawPageData struct {
		idx     int
		pageNum int
		data    *rawdata.PageData
		err     error
	}

	numCores := runtime.NumCPU()
	ioWorkers := min(numCores*2, len(pageFiles))
	numWorkers := min(numCores*3, len(pageFiles))

	pageChan := make(chan int, len(pageFiles))
	rawChan := make(chan rawPageData, len(pageFiles))
	resultChan := make(chan pageResult, numWorkers*4)

	ioWg := sync.WaitGroup{}
	for range ioWorkers {
		ioWg.Add(1)
		go func() {
			defer ioWg.Done()
			for idx := range pageChan {
				pageFile := pageFiles[idx]
				pageNum := extractPageNum(pageFile)
				rawData, err := readRawPageData(pageFile)
				rawChan <- rawPageData{idx: idx, pageNum: pageNum, data: rawData, err: err}
				Logger.Debug("read raw page", "page", pageNum, "err", err)
			}
		}()
	}

	go func() {
		ioWg.Wait()
		close(rawChan)
	}()

	cpuWg := sync.WaitGroup{}
	for range numWorkers {
		cpuWg.Add(1)
		go func() {
			defer cpuWg.Done()
			for raw := range rawChan {
				if raw.err != nil {
					resultChan <- pageResult{idx: raw.idx, pageNum: raw.pageNum, json: nil, err: raw.err}
					continue
				}

				buf := bufferPool.Get().(*bytes.Buffer)
				buf.Reset()

				err := processRawPage(raw.data, buf)
				if err != nil {
					bufferPool.Put(buf)
					resultChan <- pageResult{idx: raw.idx, pageNum: raw.pageNum, json: nil, err: err}
					continue
				}

				result := buf.Bytes()
				if len(result) > 0 && result[len(result)-1] == '\n' {
					result = result[:len(result)-1]
				}
				output := append([]byte(nil), result...)

				buf.Reset()
				bufferPool.Put(buf)

				resultChan <- pageResult{idx: raw.idx, pageNum: raw.pageNum, json: output, err: nil}
				Logger.Debug("processed page", "page", raw.pageNum)
			}
		}()
	}

	go func() {
		cpuWg.Wait()
		close(resultChan)
	}()

	go func() {
		for i := range pageFiles {
			pageChan <- i
		}
		close(pageChan)
	}()

	outputFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		Logger.Error("output file error", "err", err)
		return err
	}
	defer outputFile.Close()

	writer := bufio.NewWriterSize(outputFile, 1<<20)
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

	pending := make(map[int]pageResult, len(pageFiles))

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

	if _, err := writer.WriteString("]\n"); err != nil {
		Logger.Error("write error", "err", err)
		return err
	}
	if err := writer.Flush(); err != nil {
		Logger.Error("write error", "err", err)
		return err
	}
	if err := outputFile.Close(); err != nil {
		Logger.Error("output file error", "err", err)
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
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")

	memprofile := flag.String("memprofile", "", "write memory profile to file")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create CPU profile: %v\n", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: ./tojson <input.pdf> <output_json>")
		os.Exit(1)
	}

	err := pdfToJson(args[0], args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create memory profile: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			fmt.Fprintf(os.Stderr, "Could not write memory profile: %v\n", err)
			os.Exit(1)
		}
	}
}
