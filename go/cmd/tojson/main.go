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

type pageTask struct {
	idx      int
	pageNum  int
	pageFile string
}

type pageResult struct {
	idx     int
	pageNum int
	json    []byte
	err     error
}

//export pdf_to_json
func pdf_to_json(pdf_path *C.char, output_file *C.char) C.int {
	pdfPath, outputFile := C.GoString(pdf_path), C.GoString(output_file)
	err := pdfToJson(pdfPath, outputFile)
	if err == nil {
		return 0
	}
	Logger.Error("conversion failed", "err", err)
	return -1
}

//export pdf_to_json_with_error
func pdf_to_json_with_error(pdf_path *C.char, output_file *C.char) *C.char {
	err := pdfToJson(C.GoString(pdf_path), C.GoString(output_file))
	if err == nil {
		return nil
	}
	Logger.Error("conversion failed", "err", err)
	return C.CString(err.Error())
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

func processPage(task pageTask) pageResult {
	rawPage, err := readRawPageData(task.pageFile)
	if err != nil {
		return pageResult{idx: task.idx, pageNum: task.pageNum, err: err}
	}

	buf := bufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()
	if err := processRawPage(rawPage, buf); err != nil {
		return pageResult{idx: task.idx, pageNum: task.pageNum, err: err}
	}

	data := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	return pageResult{
		idx: task.idx, pageNum: task.pageNum, json: append([]byte(nil), data...),
	}
}

func writeOrderedPages(writer *bufio.Writer, pageFiles []string) error {
	if _, err := writer.WriteString("["); err != nil {
		return err
	}
	if len(pageFiles) == 0 {
		_, err := writer.WriteString("]\n")
		return err
	}

	workerCount := min(max(runtime.NumCPU()*3, 1), len(pageFiles))
	window := min(workerCount*2, len(pageFiles))
	jobs := make(chan pageTask, window)
	results := make(chan pageResult, window)

	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range jobs {
				results <- processPage(task)
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	nextDispatch := 0
	dispatch := func() {
		jobs <- pageTask{
			idx: nextDispatch, pageNum: extractPageNum(pageFiles[nextDispatch]),
			pageFile: pageFiles[nextDispatch],
		}
		nextDispatch++
	}
	for nextDispatch < window {
		dispatch()
	}
	jobsClosed := nextDispatch == len(pageFiles)
	if jobsClosed {
		close(jobs)
	}

	pending := make(map[int]pageResult, window)
	nextWrite := 0
	wroteAny := false
	var firstErr error
	for result := range results {
		pending[result.idx] = result
		for {
			next, ready := pending[nextWrite]
			if !ready {
				break
			}
			if next.err != nil && firstErr == nil {
				firstErr = fmt.Errorf("process page %d: %w", next.pageNum, next.err)
			}
			if firstErr == nil {
				if wroteAny {
					_, firstErr = writer.WriteString(",")
				}
				if firstErr == nil {
					_, firstErr = writer.Write(next.json)
				}
				wroteAny = true
			}
			delete(pending, nextWrite)
			nextWrite++
			if nextDispatch < len(pageFiles) {
				dispatch()
				if nextDispatch == len(pageFiles) {
					close(jobs)
					jobsClosed = true
				}
			}
		}
	}
	if !jobsClosed {
		close(jobs)
	}
	if firstErr != nil {
		return firstErr
	}
	if nextWrite != len(pageFiles) {
		return fmt.Errorf("processed %d of %d pages", nextWrite, len(pageFiles))
	}
	_, err := writer.WriteString("]\n")
	return err
}

func writeJSONDocument(outputPath string, pageFiles []string) (err error) {
	directory := filepath.Dir(outputPath)
	temp, err := os.CreateTemp(directory, ".fibrum-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		temp.Close()
		if err != nil {
			os.Remove(tempPath)
		}
	}()

	if err = temp.Chmod(0644); err != nil {
		return err
	}
	writer := bufio.NewWriterSize(temp, 1<<20)
	if err = writeOrderedPages(writer, pageFiles); err != nil {
		return err
	}
	if err = writer.Flush(); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if removeErr := os.Remove(outputPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
	}
	err = os.Rename(tempPath, outputPath)
	return err
}

func pathsReferToSameFile(first, second string) (bool, error) {
	firstInfo, err := os.Stat(first)
	if err != nil {
		return false, err
	}
	secondInfo, err := os.Stat(second)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(firstInfo, secondInfo), nil
}

func pdfToJson(pdfPath, outputPath string) error {
	startTotal := time.Now()
	startRaw := time.Now()

	Logger.Info("beginning conversion...")
	Logger.Debug("paths", "pdf", pdfPath, "output", outputPath)
	if same, err := pathsReferToSameFile(pdfPath, outputPath); err != nil {
		return err
	} else if same {
		return fmt.Errorf("input and output refer to the same file")
	}

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

	if err := writeJSONDocument(outputPath, pageFiles); err != nil {
		Logger.Error("output error", "err", err)
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
