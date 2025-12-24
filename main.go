package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

func main() {
	root := flag.String("root", ".", "root directory to scan")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "number of hashing workers")
	tmp := flag.String("tmp", "", "temp directory for external sorting (default: system temp)")
	sortParallel := flag.Int("sort-parallel", runtime.GOMAXPROCS(0), "parallelism for external sort (GNU sort --parallel)")
	sortMem := flag.String("sort-mem", "", "memory limit for external sort (GNU sort -S), e.g. 25% or 8G (empty uses sort default)")
	keepTemp := flag.Bool("keep-temp", false, "keep temp files (for debugging)")
	flag.Parse()

	if err := run(*root, *workers, *tmp, *sortParallel, *sortMem, *keepTemp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, workers int, tmp string, sortParallel int, sortMem string, keepTemp bool) error {
	if workers < 1 {
		workers = 1
	}
	if sortParallel < 1 {
		sortParallel = 1
	}
	if _, err := exec.LookPath("sort"); err != nil {
		return errors.New("missing dependency: `sort` not found in PATH (required for very large scans)")
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

	if err := externalSortZ(unsorted, sorted, workDir, sortParallel, sortMem); err != nil {
		return err
	}

	hashErrCount, dupGroups, err := scanSortedBySizeAndEmitDuplicates(sorted, workDir, workers, sortParallel, sortMem)
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

		// Record format (NUL-delimited records for sort -z):
		//   <20-digit-zero-padded-size><space><path><NUL>
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
	// 20 digits is enough for int64 (max is 19 digits).
	if _, err := w.WriteString(fmt.Sprintf("%020d", size)); err != nil {
		return err
	}
	if err := w.WriteByte(' '); err != nil {
		return err
	}
	if _, err := w.WriteString(path); err != nil {
		return err
	}
	return w.WriteByte(0)
}

func externalSortZ(inPath string, outPath string, tmpDir string, parallel int, mem string) error {
	args := []string{"-z"}
	args = append(args, "--temporary-directory="+tmpDir)
	if parallel > 0 {
		args = append(args, fmt.Sprintf("--parallel=%d", parallel))
	}
	if mem != "" {
		args = append(args, "-S", mem)
	}
	args = append(args, "-o", outPath, inPath)

	cmd := exec.Command("sort", args...)
	// Speed up comparisons for bytewise ordering.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("external sort failed: %w", err)
	}
	return nil
}

func scanSortedBySizeAndEmitDuplicates(sortedPath string, workDir string, workers int, sortParallel int, sortMem string) (hashErrCount int, dupGroups int, _ error) {
	f, err := os.Open(sortedPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open sorted size file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Records are typically small (size key + path), but make the buffer generous.
	sc.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	sc.Split(splitNUL)

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
			groupHashErr, groupDups, err = hasher.CloseAndEmitDuplicates(sortParallel, sortMem)
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

	for sc.Scan() {
		size, path, perr := parseSizeRecord(sc.Bytes())
		if perr != nil {
			return hashErrCount, dupGroups, perr
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
			// Now we know this size occurs at least twice -> duplicates possible.
			hasher, err = newGroupHasher(workDir, curSize, workers)
			if err != nil {
				return hashErrCount, dupGroups, err
			}
			hasher.Feed(firstPath)
			hasher.Feed(path)
			continue
		}
		// curCount >= 3
		if hasher != nil {
			hasher.Feed(path)
		}
	}
	if err := sc.Err(); err != nil {
		return hashErrCount, dupGroups, fmt.Errorf("scan sorted size file: %w", err)
	}
	if err := flushGroup(); err != nil {
		return hashErrCount, dupGroups, err
	}
	return hashErrCount, dupGroups, nil
}

func parseSizeRecord(rec []byte) (size int64, path string, _ error) {
	// rec is a single record without the trailing NUL.
	// Expected: 20 digits + space + path
	if len(rec) < 22 {
		return 0, "", fmt.Errorf("invalid size record (too short): %q", string(rec))
	}
	if rec[20] != ' ' {
		return 0, "", fmt.Errorf("invalid size record (missing delimiter): %q", string(rec))
	}
	sz, err := strconv.ParseInt(string(rec[:20]), 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid size in record: %w", err)
	}
	return sz, string(rec[21:]), nil
}

type hashResult struct {
	path string
	sum  string
	err  error
}

type groupHasher struct {
	size            int64
	workers         int
	workDir         string
	hashUnsorted    string
	hashSorted      string
	jobCh           chan string
	resCh           chan hashResult
	workerWg        sync.WaitGroup
	writerWg        sync.WaitGroup
	outFile         *os.File
	outWriter       *bufio.Writer
	closedOnceGuard sync.Once
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
				fmt.Fprintf(os.Stderr, "hash error: %s: %v\n", res.path, res.err)
				continue
			}
			_ = writeHashRecord(h.outWriter, res.sum, res.path)
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

func (h *groupHasher) CloseAndEmitDuplicates(sortParallel int, sortMem string) (hashErrCount int, dupGroups int, _ error) {
	var closeErr error
	h.closedOnceGuard.Do(func() {
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

	if err := externalSortZ(h.hashUnsorted, h.hashSorted, h.workDir, sortParallel, sortMem); err != nil {
		return 0, 0, err
	}

	outGroups, outErrCount, err := emitDuplicatesForSizeFromSortedHash(h.size, h.hashSorted)
	if err != nil {
		return 0, 0, err
	}

	_ = os.Remove(h.hashUnsorted)
	_ = os.Remove(h.hashSorted)
	return outErrCount, outGroups, nil
}

func writeHashRecord(w *bufio.Writer, sha256hex string, path string) error {
	// Record format (NUL-delimited records for sort -z):
	//   <64-hex-sha256><space><path><NUL>
	if len(sha256hex) != 64 {
		return fmt.Errorf("invalid sha256 length for %q", path)
	}
	if _, err := w.WriteString(sha256hex); err != nil {
		return err
	}
	if err := w.WriteByte(' '); err != nil {
		return err
	}
	if _, err := w.WriteString(path); err != nil {
		return err
	}
	return w.WriteByte(0)
}

func emitDuplicatesForSizeFromSortedHash(size int64, sortedHashPath string) (dupGroups int, hashErrCount int, _ error) {
	f, err := os.Open(sortedHashPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open sorted hash file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	sc.Split(splitNUL)

	var (
		curHash   string
		curCount  int64
		firstPath string
		printed   bool
	)

	flush := func() {
		if printed {
			fmt.Println()
		}
		curHash = ""
		curCount = 0
		firstPath = ""
		printed = false
	}

	for sc.Scan() {
		hash, path, perr := parseHashRecord(sc.Bytes())
		if perr != nil {
			return dupGroups, hashErrCount, perr
		}

		if curHash == "" {
			curHash = hash
		}
		if hash != curHash {
			flush()
			curHash = hash
		}

		curCount++
		if curCount == 1 {
			firstPath = path
			continue
		}
		if curCount == 2 {
			dupGroups++
			fmt.Printf("Duplicate group (size=%d bytes, sha256=%s):\n", size, curHash)
			fmt.Printf("  %s\n", firstPath)
			fmt.Printf("  %s\n", path)
			printed = true
			continue
		}
		// curCount >= 3
		if printed {
			fmt.Printf("  %s\n", path)
		}
	}
	if err := sc.Err(); err != nil {
		return dupGroups, hashErrCount, fmt.Errorf("scan sorted hash file: %w", err)
	}
	if printed {
		fmt.Println()
	}
	return dupGroups, hashErrCount, nil
}

func parseHashRecord(rec []byte) (hash string, path string, _ error) {
	// Expected: 64 hex + space + path
	if len(rec) < 66 {
		return "", "", fmt.Errorf("invalid hash record (too short): %q", string(rec))
	}
	if rec[64] != ' ' {
		return "", "", fmt.Errorf("invalid hash record (missing delimiter): %q", string(rec))
	}
	return string(rec[:64]), string(rec[65:]), nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	// 1 MiB buffer: good throughput without being too memory-heavy.
	buf := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func splitNUL(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		// Last record without NUL terminator (shouldn't happen, but be lenient).
		return len(data), data, nil
	}
	return 0, nil, nil
}
