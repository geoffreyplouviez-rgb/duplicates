package main

import (
	"bufio"
	"bytes"
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

func main() {
	root := flag.String("root", ".", "root directory to scan")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "number of hashing workers")
	tmp := flag.String("tmp", "", "temp directory for external sorting (default: system temp)")
	sortMem := flag.String("sort-mem", "512M", "memory budget per external-sort pass (e.g. 512M, 4G)")
	mergeFanIn := flag.Int("merge-fan-in", 128, "max number of runs to merge at once")
	keepTemp := flag.Bool("keep-temp", false, "keep temp files (for debugging)")
	flag.Parse()

	if err := run(*root, *workers, *tmp, *sortMem, *mergeFanIn, *keepTemp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, workers int, tmp string, sortMem string, mergeFanIn int, keepTemp bool) error {
	if workers < 1 {
		workers = 1
	}
	if mergeFanIn < 2 {
		mergeFanIn = 2
	}
	memBytes, err := parseByteSize(sortMem)
	if err != nil {
		return err
	}

	if tmp == "" {
		tmp = os.TempDir()
	}

	workDir, err := os.MkdirTemp(tmp, "dup-scan-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	if !keepTemp {
		defer os.RemoveAll(workDir)
	}

	unsorted := filepath.Join(workDir, "files.unsorted")
	sorted := filepath.Join(workDir, "files.sorted")

	walkErrCount, fileCount, err := writeSizeRecords(root, unsorted)
	if err != nil {
		return err
	}
	if walkErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while walking\n", walkErrCount)
	}
	if fileCount == 0 {
		fmt.Println("No duplicates found.")
		return nil
	}

	if err := externalSortSizeRecords(unsorted, sorted, workDir, memBytes, mergeFanIn); err != nil {
		return err
	}

	hashErrCount, dupGroups, err := scanSortedBySizeAndEmitDuplicates(sorted, workDir, workers, memBytes, mergeFanIn)
	if err != nil {
		return err
	}
	if hashErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while hashing\n", hashErrCount)
	}
	if dupGroups == 0 {
		fmt.Println("No duplicates found.")
	}
	return nil
}

// ---- Walk + write records ----

func writeSizeRecords(root string, outPath string) (walkErrCount int, fileCount int64, _ error) {
	f, err := os.Create(outPath)
	if err != nil {
		return 0, 0, fmt.Errorf("create size record file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 4*1024*1024)
	defer w.Flush()

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			walkErrCount++
			fmt.Fprintf(os.Stderr, "walk error: %s: %v\n", path, err)
			return nil
		}

		// Skip symlinks to avoid loops / surprising behavior.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			walkErrCount++
			fmt.Fprintf(os.Stderr, "stat error: %s: %v\n", path, infoErr)
			return nil
		}

		// Record format (binary, length-delimited):
		//   uvarint(size) + uvarint(pathLen) + pathBytes
		if err := writeSizeRecord(w, info.Size(), path); err != nil {
			return err
		}
		fileCount++
		return nil
	}

	if err := filepath.WalkDir(root, walkFn); err != nil {
		// WalkDir only returns a terminal error (e.g., invalid root); per-entry
		// errors are handled inside walkFn.
		return walkErrCount + 1, fileCount, fmt.Errorf("walk fatal error: %w", err)
	}
	if err := w.Flush(); err != nil {
		return walkErrCount, fileCount, fmt.Errorf("flush size record file: %w", err)
	}
	if err := f.Close(); err != nil {
		return walkErrCount, fileCount, fmt.Errorf("close size record file: %w", err)
	}
	return walkErrCount, fileCount, nil
}

func writeSizeRecord(w *bufio.Writer, size int64, path string) error {
	if size < 0 {
		size = 0
	}
	if err := writeUvarint(w, uint64(size)); err != nil {
		return err
	}
	if err := writeUvarint(w, uint64(len(path))); err != nil {
		return err
	}
	_, err := w.WriteString(path)
	return err
}

// ---- External sort (in-Go) ----

type sizeRec struct {
	size int64
	path string
}

func externalSortSizeRecords(inPath, outPath, workDir string, memBytes int64, mergeFanIn int) error {
	runs, err := makeSizeRuns(inPath, workDir, memBytes)
	if err != nil {
		return err
	}
	defer func() {
		for _, p := range runs {
			_ = os.Remove(p)
		}
	}()
	return mergeSizeRuns(runs, outPath, workDir, mergeFanIn)
}

func makeSizeRuns(inPath, workDir string, memBytes int64) ([]string, error) {
	if memBytes < 32*1024*1024 {
		memBytes = 32 * 1024 * 1024
	}

	f, err := os.Open(inPath)
	if err != nil {
		return nil, fmt.Errorf("open size records: %w", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 4*1024*1024)
	var (
		recs   []sizeRec
		approx int64
		runs   []string
	)

	flush := func() error {
		if len(recs) == 0 {
			return nil
		}
		sort.Slice(recs, func(i, j int) bool {
			if recs[i].size != recs[j].size {
				return recs[i].size < recs[j].size
			}
			return recs[i].path < recs[j].path
		})

		rf, err := os.CreateTemp(workDir, "run-size-*.bin")
		if err != nil {
			return fmt.Errorf("create run: %w", err)
		}
		w := bufio.NewWriterSize(rf, 4*1024*1024)
		for _, rec := range recs {
			if err := writeSizeRecord(w, rec.size, rec.path); err != nil {
				_ = rf.Close()
				_ = os.Remove(rf.Name())
				return fmt.Errorf("write run: %w", err)
			}
		}
		if err := w.Flush(); err != nil {
			_ = rf.Close()
			_ = os.Remove(rf.Name())
			return fmt.Errorf("flush run: %w", err)
		}
		if err := rf.Close(); err != nil {
			_ = os.Remove(rf.Name())
			return fmt.Errorf("close run: %w", err)
		}

		runs = append(runs, rf.Name())
		recs = recs[:0]
		approx = 0
		return nil
	}

	for {
		size, path, ok, err := readSizeRecord(r)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		recs = append(recs, sizeRec{size: size, path: path})
		approx += int64(len(path)) + 32
		if approx >= memBytes {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return runs, nil
}

type sizeHeapItem struct {
	rec    sizeRec
	runIdx int
}

type sizeHeap []sizeHeapItem

func (h sizeHeap) Len() int { return len(h) }
func (h sizeHeap) Less(i, j int) bool {
	if h[i].rec.size != h[j].rec.size {
		return h[i].rec.size < h[j].rec.size
	}
	return h[i].rec.path < h[j].rec.path
}
func (h sizeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *sizeHeap) Push(x any)   { *h = append(*h, x.(sizeHeapItem)) }
func (h *sizeHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func mergeSizeRuns(runPaths []string, outPath string, workDir string, mergeFanIn int) error {
	if len(runPaths) == 0 {
		of, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create sorted output: %w", err)
		}
		return of.Close()
	}
	if mergeFanIn < 2 {
		mergeFanIn = 2
	}

	runs := append([]string(nil), runPaths...)
	for len(runs) > mergeFanIn {
		var next []string
		for i := 0; i < len(runs); i += mergeFanIn {
			end := i + mergeFanIn
			if end > len(runs) {
				end = len(runs)
			}
			tmpOut, err := os.CreateTemp(workDir, "run-merge-size-*.bin")
			if err != nil {
				return fmt.Errorf("create merge run: %w", err)
			}
			tmpOutPath := tmpOut.Name()
			_ = tmpOut.Close()
			if err := mergeSizeRunsOne(runs[i:end], tmpOutPath); err != nil {
				_ = os.Remove(tmpOutPath)
				return err
			}
			next = append(next, tmpOutPath)
		}
		for _, p := range runs {
			_ = os.Remove(p)
		}
		runs = next
	}
	return mergeSizeRunsOne(runs, outPath)
}

func mergeSizeRunsOne(runPaths []string, outPath string) error {
	files := make([]*os.File, 0, len(runPaths))
	readers := make([]*bufio.Reader, 0, len(runPaths))
	for _, p := range runPaths {
		f, err := os.Open(p)
		if err != nil {
			for _, of := range files {
				_ = of.Close()
			}
			return fmt.Errorf("open run: %w", err)
		}
		files = append(files, f)
		readers = append(readers, bufio.NewReaderSize(f, 2*1024*1024))
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()

	outF, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create merged output: %w", err)
	}
	defer outF.Close()
	outW := bufio.NewWriterSize(outF, 4*1024*1024)
	defer outW.Flush()

	h := &sizeHeap{}
	heap.Init(h)
	for i, r := range readers {
		sz, path, ok, err := readSizeRecord(r)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		heap.Push(h, sizeHeapItem{rec: sizeRec{size: sz, path: path}, runIdx: i})
	}

	for h.Len() > 0 {
		it := heap.Pop(h).(sizeHeapItem)
		if err := writeSizeRecord(outW, it.rec.size, it.rec.path); err != nil {
			return err
		}
		sz, path, ok, err := readSizeRecord(readers[it.runIdx])
		if err != nil {
			return err
		}
		if ok {
			heap.Push(h, sizeHeapItem{rec: sizeRec{size: sz, path: path}, runIdx: it.runIdx})
		}
	}

	if err := outW.Flush(); err != nil {
		return err
	}
	return outF.Close()
}

type hashRec struct {
	sum  [32]byte
	path string
}

func externalSortHashRecords(inPath, outPath, workDir string, memBytes int64, mergeFanIn int) error {
	runs, err := makeHashRuns(inPath, workDir, memBytes)
	if err != nil {
		return err
	}
	defer func() {
		for _, p := range runs {
			_ = os.Remove(p)
		}
	}()
	return mergeHashRuns(runs, outPath, workDir, mergeFanIn)
}

func makeHashRuns(inPath, workDir string, memBytes int64) ([]string, error) {
	if memBytes < 32*1024*1024 {
		memBytes = 32 * 1024 * 1024
	}

	f, err := os.Open(inPath)
	if err != nil {
		return nil, fmt.Errorf("open hash records: %w", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 4*1024*1024)
	var (
		recs   []hashRec
		approx int64
		runs   []string
	)

	flush := func() error {
		if len(recs) == 0 {
			return nil
		}
		sort.Slice(recs, func(i, j int) bool {
			c := bytes.Compare(recs[i].sum[:], recs[j].sum[:])
			if c != 0 {
				return c < 0
			}
			return recs[i].path < recs[j].path
		})

		rf, err := os.CreateTemp(workDir, "run-hash-*.bin")
		if err != nil {
			return fmt.Errorf("create hash run: %w", err)
		}
		w := bufio.NewWriterSize(rf, 4*1024*1024)
		for _, rec := range recs {
			if err := writeHashRecord(w, rec.sum, rec.path); err != nil {
				_ = rf.Close()
				_ = os.Remove(rf.Name())
				return fmt.Errorf("write hash run: %w", err)
			}
		}
		if err := w.Flush(); err != nil {
			_ = rf.Close()
			_ = os.Remove(rf.Name())
			return fmt.Errorf("flush hash run: %w", err)
		}
		if err := rf.Close(); err != nil {
			_ = os.Remove(rf.Name())
			return fmt.Errorf("close hash run: %w", err)
		}

		runs = append(runs, rf.Name())
		recs = recs[:0]
		approx = 0
		return nil
	}

	for {
		sum, path, ok, err := readHashRecord(r)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		recs = append(recs, hashRec{sum: sum, path: path})
		approx += int64(len(path)) + 64
		if approx >= memBytes {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return runs, nil
}

type hashHeapItem struct {
	rec    hashRec
	runIdx int
}

type hashHeap []hashHeapItem

func (h hashHeap) Len() int { return len(h) }
func (h hashHeap) Less(i, j int) bool {
	c := bytes.Compare(h[i].rec.sum[:], h[j].rec.sum[:])
	if c != 0 {
		return c < 0
	}
	return h[i].rec.path < h[j].rec.path
}
func (h hashHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *hashHeap) Push(x any)   { *h = append(*h, x.(hashHeapItem)) }
func (h *hashHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func mergeHashRuns(runPaths []string, outPath string, workDir string, mergeFanIn int) error {
	if len(runPaths) == 0 {
		of, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create sorted output: %w", err)
		}
		return of.Close()
	}
	if mergeFanIn < 2 {
		mergeFanIn = 2
	}

	runs := append([]string(nil), runPaths...)
	for len(runs) > mergeFanIn {
		var next []string
		for i := 0; i < len(runs); i += mergeFanIn {
			end := i + mergeFanIn
			if end > len(runs) {
				end = len(runs)
			}
			tmpOut, err := os.CreateTemp(workDir, "run-merge-hash-*.bin")
			if err != nil {
				return fmt.Errorf("create merge hash run: %w", err)
			}
			tmpOutPath := tmpOut.Name()
			_ = tmpOut.Close()
			if err := mergeHashRunsOne(runs[i:end], tmpOutPath); err != nil {
				_ = os.Remove(tmpOutPath)
				return err
			}
			next = append(next, tmpOutPath)
		}
		for _, p := range runs {
			_ = os.Remove(p)
		}
		runs = next
	}
	return mergeHashRunsOne(runs, outPath)
}

func mergeHashRunsOne(runPaths []string, outPath string) error {
	files := make([]*os.File, 0, len(runPaths))
	readers := make([]*bufio.Reader, 0, len(runPaths))
	for _, p := range runPaths {
		f, err := os.Open(p)
		if err != nil {
			for _, of := range files {
				_ = of.Close()
			}
			return fmt.Errorf("open hash run: %w", err)
		}
		files = append(files, f)
		readers = append(readers, bufio.NewReaderSize(f, 2*1024*1024))
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()

	outF, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create merged hash output: %w", err)
	}
	defer outF.Close()
	outW := bufio.NewWriterSize(outF, 4*1024*1024)
	defer outW.Flush()

	h := &hashHeap{}
	heap.Init(h)
	for i, r := range readers {
		sum, path, ok, err := readHashRecord(r)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		heap.Push(h, hashHeapItem{rec: hashRec{sum: sum, path: path}, runIdx: i})
	}

	for h.Len() > 0 {
		it := heap.Pop(h).(hashHeapItem)
		if err := writeHashRecord(outW, it.rec.sum, it.rec.path); err != nil {
			return err
		}
		sum, path, ok, err := readHashRecord(readers[it.runIdx])
		if err != nil {
			return err
		}
		if ok {
			heap.Push(h, hashHeapItem{rec: hashRec{sum: sum, path: path}, runIdx: it.runIdx})
		}
	}

	if err := outW.Flush(); err != nil {
		return err
	}
	return outF.Close()
}

// ---- Stream sorted-by-size groups, hash, and print duplicates ----

func scanSortedBySizeAndEmitDuplicates(sortedPath string, workDir string, workers int, memBytes int64, mergeFanIn int) (hashErrCount int, dupGroups int, _ error) {
	f, err := os.Open(sortedPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open sorted size file: %w", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 4*1024*1024)

	var (
		curSize      int64 = -1
		curCount     int64
		firstPath    string
		hasher       *groupHasher
		groupHashErr int
		groupDups    int
	)

	flushGroup := func() error {
		if hasher != nil {
			groupHashErr, groupDups, err = hasher.CloseAndEmitDuplicates(memBytes, mergeFanIn)
			if err != nil {
				return err
			}
			hashErrCount += groupHashErr
			dupGroups += groupDups
		}
		curCount = 0
		firstPath = ""
		hasher = nil
		return nil
	}

	for {
		size, path, ok, perr := readSizeRecord(r)
		if perr != nil {
			return hashErrCount, dupGroups, perr
		}
		if !ok {
			break
		}

		if curSize == -1 {
			curSize = size
		}
		if size != curSize {
			if err := flushGroup(); err != nil {
				return hashErrCount, dupGroups, err
			}
			curSize = size
		}

		curCount++
		if curCount == 1 {
			firstPath = path
			continue
		}
		if curCount == 2 {
			hasher, err = newGroupHasher(workDir, curSize, workers)
			if err != nil {
				return hashErrCount, dupGroups, err
			}
			hasher.Feed(firstPath)
			hasher.Feed(path)
			continue
		}
		if hasher != nil {
			hasher.Feed(path)
		}
	}

	if err := flushGroup(); err != nil {
		return hashErrCount, dupGroups, err
	}
	return hashErrCount, dupGroups, nil
}

type hashResult struct {
	path string
	sum  [32]byte
	err  error
}

type groupHasher struct {
	size         int64
	workers      int
	workDir      string
	hashUnsorted string
	hashSorted   string
	jobCh        chan string
	resCh        chan hashResult
	workerWg     sync.WaitGroup
	writerWg     sync.WaitGroup
	outFile      *os.File
	outWriter    *bufio.Writer

	hashErrCount atomic.Int64
	writeErrMu   sync.Mutex
	writeErr     error
	closedOnce   sync.Once
}

func newGroupHasher(workDir string, size int64, workers int) (*groupHasher, error) {
	if workers < 1 {
		workers = 1
	}
	f, err := os.CreateTemp(workDir, fmt.Sprintf("hash-%020d-*.unsorted", size))
	if err != nil {
		return nil, fmt.Errorf("create temp hash file: %w", err)
	}

	h := &groupHasher{
		size:         size,
		workers:      workers,
		workDir:      workDir,
		hashUnsorted: f.Name(),
		hashSorted:   f.Name() + ".sorted",
		jobCh:        make(chan string, 4096),
		resCh:        make(chan hashResult, 4096),
		outFile:      f,
		outWriter:    bufio.NewWriterSize(f, 4*1024*1024),
	}

	h.writerWg.Add(1)
	go func() {
		defer h.writerWg.Done()
		for res := range h.resCh {
			if res.err != nil {
				h.hashErrCount.Add(1)
				fmt.Fprintf(os.Stderr, "hash error: %s: %v\n", res.path, res.err)
				continue
			}
			if err := writeHashRecord(h.outWriter, res.sum, res.path); err != nil {
				h.writeErrMu.Lock()
				if h.writeErr == nil {
					h.writeErr = err
				}
				h.writeErrMu.Unlock()
			}
		}
	}()

	h.workerWg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer h.workerWg.Done()
			for path := range h.jobCh {
				sum, err := sha256File(path)
				h.resCh <- hashResult{path: path, sum: sum, err: err}
			}
		}()
	}

	return h, nil
}

func (h *groupHasher) Feed(path string) {
	h.jobCh <- path
}

func (h *groupHasher) CloseAndEmitDuplicates(memBytes int64, mergeFanIn int) (hashErrCount int, dupGroups int, _ error) {
	var closeErr error
	h.closedOnce.Do(func() {
		close(h.jobCh)
		h.workerWg.Wait()
		close(h.resCh)
		h.writerWg.Wait()

		if err := h.outWriter.Flush(); err != nil {
			closeErr = fmt.Errorf("flush hash record file: %w", err)
			return
		}
		if err := h.outFile.Close(); err != nil {
			closeErr = fmt.Errorf("close hash record file: %w", err)
			return
		}
	})
	if closeErr != nil {
		return 0, 0, closeErr
	}

	h.writeErrMu.Lock()
	we := h.writeErr
	h.writeErrMu.Unlock()
	if we != nil {
		return 0, 0, we
	}

	if err := externalSortHashRecords(h.hashUnsorted, h.hashSorted, h.workDir, memBytes, mergeFanIn); err != nil {
		return 0, 0, err
	}

	outGroups, outErrCount, err := emitDuplicatesForSizeFromSortedHash(h.size, h.hashSorted)
	if err != nil {
		return 0, 0, err
	}

	_ = os.Remove(h.hashUnsorted)
	_ = os.Remove(h.hashSorted)
	return int(h.hashErrCount.Load()) + outErrCount, outGroups, nil
}

func writeHashRecord(w *bufio.Writer, sum [32]byte, path string) error {
	// Record format (binary, length-delimited):
	//   32 bytes sha256 + uvarint(pathLen) + pathBytes
	if _, err := w.Write(sum[:]); err != nil {
		return err
	}
	if err := writeUvarint(w, uint64(len(path))); err != nil {
		return err
	}
	_, err := w.WriteString(path)
	return err
}

func emitDuplicatesForSizeFromSortedHash(size int64, sortedHashPath string) (dupGroups int, hashErrCount int, _ error) {
	f, err := os.Open(sortedHashPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open sorted hash file: %w", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 4*1024*1024)

	var (
		curHash   [32]byte
		curCount  int64
		firstPath string
		printed   bool
	)

	flush := func() {
		if printed {
			fmt.Println()
		}
		curHash = [32]byte{}
		curCount = 0
		firstPath = ""
		printed = false
	}

	for {
		hv, path, ok, perr := readHashRecord(r)
		if perr != nil {
			return dupGroups, hashErrCount, perr
		}
		if !ok {
			break
		}

		if curCount == 0 {
			curHash = hv
		}
		if hv != curHash {
			flush()
			curHash = hv
		}

		curCount++
		if curCount == 1 {
			firstPath = path
			continue
		}
		if curCount == 2 {
			dupGroups++
			fmt.Printf("Duplicate group (size=%d bytes, sha256=%s):\n", size, hex.EncodeToString(curHash[:]))
			fmt.Printf("  %s\n", firstPath)
			fmt.Printf("  %s\n", path)
			printed = true
			continue
		}
		if printed {
			fmt.Printf("  %s\n", path)
		}
	}

	if printed {
		fmt.Println()
	}
	return dupGroups, hashErrCount, nil
}

func sha256File(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return [32]byte{}, err
	}
	sum := h.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out, nil
}

// ---- Binary record IO helpers ----

func writeUvarint(w *bufio.Writer, x uint64) error {
	var buf [10]byte
	n := binary.PutUvarint(buf[:], x)
	_, err := w.Write(buf[:n])
	return err
}

func readSizeRecord(r *bufio.Reader) (size int64, path string, ok bool, _ error) {
	sz, err := binary.ReadUvarint(r)
	if err != nil {
		if isEOF(err) {
			return 0, "", false, nil
		}
		return 0, "", false, fmt.Errorf("read size: %w", err)
	}
	pl, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, "", false, fmt.Errorf("read path length: %w", err)
	}
	if pl > uint64(^uint(0)) {
		return 0, "", false, fmt.Errorf("path too large: %d", pl)
	}
	b := make([]byte, int(pl))
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, "", false, fmt.Errorf("read path: %w", err)
	}
	return int64(sz), string(b), true, nil
}

func readHashRecord(r *bufio.Reader) (sum [32]byte, path string, ok bool, _ error) {
	_, err := io.ReadFull(r, sum[:])
	if err != nil {
		if isEOF(err) {
			return [32]byte{}, "", false, nil
		}
		return [32]byte{}, "", false, fmt.Errorf("read hash: %w", err)
	}
	pl, err := binary.ReadUvarint(r)
	if err != nil {
		return [32]byte{}, "", false, fmt.Errorf("read path length: %w", err)
	}
	if pl > uint64(^uint(0)) {
		return [32]byte{}, "", false, fmt.Errorf("path too large: %d", pl)
	}
	b := make([]byte, int(pl))
	if _, err := io.ReadFull(r, b); err != nil {
		return [32]byte{}, "", false, fmt.Errorf("read path: %w", err)
	}
	return sum, string(b), true, nil
}

func isEOF(err error) bool {
	return err == io.EOF || err == io.ErrUnexpectedEOF
}

// ---- Misc ----

func parseByteSize(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("sort-mem cannot be empty")
	}
	last := s[len(s)-1]
	mult := int64(1)
	num := s
	switch last {
	case 'K', 'k':
		mult = 1024
		num = s[:len(s)-1]
	case 'M', 'm':
		mult = 1024 * 1024
		num = s[:len(s)-1]
	case 'G', 'g':
		mult = 1024 * 1024 * 1024
		num = s[:len(s)-1]
	case 'T', 't':
		mult = 1024 * 1024 * 1024 * 1024
		num = s[:len(s)-1]
	}
	v, err := strconv.ParseInt(num, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("invalid sort-mem %q (examples: 512M, 4G)", s)
	}
	return v * mult, nil
}
