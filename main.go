package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
)

func main() {
	root := flag.String("root", ".", "root directory to scan")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "number of hashing workers")
	quickBytes := flag.Int64("quick-bytes", 4096, "bytes per sample for quick check (0 to disable and hash full sha256 immediately)")
	flag.Parse()

	if err := run(*root, *workers, *quickBytes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, workers int, quickBytes int64) error {
	if workers < 1 {
		workers = 1
	}
	if quickBytes < 0 {
		quickBytes = 0
	}

	recs, quickErrCount, fullErrCount, walkErrCount, fileCount, err := scanAndHashOnePass(root, workers, quickBytes)
	if err != nil {
		return err
	}
	if walkErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while walking\n", walkErrCount)
	}
	if quickErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while quick-check hashing\n", quickErrCount)
	}
	if fullErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while full hashing\n", fullErrCount)
	}
	if fileCount == 0 {
		fmt.Println("No duplicates found.")
		return nil
	}

	sort.Slice(recs, func(i, j int) bool {
		if recs[i].size != recs[j].size {
			return recs[i].size < recs[j].size
		}
		if recs[i].sum != recs[j].sum {
			return lessSum(recs[i].sum, recs[j].sum)
		}
		return recs[i].path < recs[j].path
	})

	dupGroups := printDuplicateGroups(recs)
	if dupGroups == 0 {
		fmt.Println("No duplicates found.")
	}
	return nil
}

// ---- Single-pass: hash only when a size repeats ----

type fileJob struct {
	path string
	size int64
}

type hashedRec struct {
	size int64
	sum  [32]byte
	path string
}

type hashResult struct {
	rec hashedRec
	err error
}

type quickRec struct {
	size int64
	sum  [32]byte
	path string
}

type quickResult struct {
	rec quickRec
	err error
}

func scanAndHashOnePass(root string, workers int, quickBytes int64) (recs []hashedRec, quickErrCount int64, fullErrCount int64, walkErrCount int64, fileCount int64, _ error) {
	if workers < 1 {
		workers = 1
	}

	// Phase 1: quick fingerprint (small samples) to avoid hashing huge files fully.
	quickJobCh := make(chan fileJob, 4096)
	quickResCh := make(chan quickResult, 4096)

	var workerWg sync.WaitGroup
	workerWg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer workerWg.Done()
			for job := range quickJobCh {
				sum, err := quickDigestFile(job.path, job.size, quickBytes)
				quickResCh <- quickResult{
					rec: quickRec{size: job.size, sum: sum, path: job.path},
					err: err,
				}
			}
		}()
	}

	var walkWg sync.WaitGroup
	walkWg.Add(1)
	var walkFatalErr error
	go func() {
		defer walkWg.Done()

		firstBySize := make(map[int64]string, 1024)      // size -> first seen path
		candidateBySize := make(map[int64]struct{}, 512) // sizes we've already started hashing

		walkFn := func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				walkErrCount++
				fmt.Fprintf(os.Stderr, "walk error: %s: %v\n", path, err)
				return nil
			}

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

			sz := info.Size()
			if sz < 0 {
				sz = 0
			}
			fileCount++

			if _, ok := candidateBySize[sz]; ok {
				quickJobCh <- fileJob{path: path, size: sz}
				return nil
			}
			if first, ok := firstBySize[sz]; ok {
				delete(firstBySize, sz)
				candidateBySize[sz] = struct{}{}
				quickJobCh <- fileJob{path: first, size: sz}
				quickJobCh <- fileJob{path: path, size: sz}
				return nil
			}
			firstBySize[sz] = path
			return nil
		}

		walkFatalErr = filepath.WalkDir(root, walkFn)
		close(quickJobCh)
	}()

	go func() {
		workerWg.Wait()
		close(quickResCh)
	}()

	var quickRecs []quickRec
	for res := range quickResCh {
		if res.err != nil {
			quickErrCount++
			fmt.Fprintf(os.Stderr, "quick-hash error: %s: %v\n", res.rec.path, res.err)
			continue
		}
		quickRecs = append(quickRecs, res.rec)
	}

	walkWg.Wait()
	if walkFatalErr != nil {
		return nil, quickErrCount, fullErrCount, walkErrCount, fileCount, fmt.Errorf("walk fatal error: %w", walkFatalErr)
	}

	// Decide which files need the full SHA-256 based on (size, quickSum).
	sort.Slice(quickRecs, func(i, j int) bool {
		if quickRecs[i].size != quickRecs[j].size {
			return quickRecs[i].size < quickRecs[j].size
		}
		if quickRecs[i].sum != quickRecs[j].sum {
			return lessSum(quickRecs[i].sum, quickRecs[j].sum)
		}
		return quickRecs[i].path < quickRecs[j].path
	})

	// Phase 2: full SHA-256 only for quick-collision groups.
	fullJobCh := make(chan fileJob, 4096)
	fullResCh := make(chan hashResult, 4096)

	var fullWg sync.WaitGroup
	fullWg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer fullWg.Done()
			for job := range fullJobCh {
				sum, err := sha256File(job.path)
				fullResCh <- hashResult{
					rec: hashedRec{size: job.size, sum: sum, path: job.path},
					err: err,
				}
			}
		}()
	}
	go func() {
		fullWg.Wait()
		close(fullResCh)
	}()

	enqueueFull := func(path string, size int64) {
		fullJobCh <- fileJob{path: path, size: size}
	}

	// Identify groups with count > 1.
	var (
		curSize     int64 = -1
		curQuickSum [32]byte
		curCount    int
		firstPath   string
	)
	flush := func() {
		curSize = -1
		curQuickSum = [32]byte{}
		curCount = 0
		firstPath = ""
	}
	for _, qr := range quickRecs {
		if curCount == 0 {
			curSize = qr.size
			curQuickSum = qr.sum
		}
		if qr.size != curSize || qr.sum != curQuickSum {
			flush()
			curSize = qr.size
			curQuickSum = qr.sum
		}

		curCount++
		if curCount == 1 {
			firstPath = qr.path
			continue
		}
		if curCount == 2 {
			enqueueFull(firstPath, curSize)
			enqueueFull(qr.path, curSize)
			continue
		}
		enqueueFull(qr.path, curSize)
	}
	close(fullJobCh)

	for res := range fullResCh {
		if res.err != nil {
			fullErrCount++
			fmt.Fprintf(os.Stderr, "hash error: %s: %v\n", res.rec.path, res.err)
			continue
		}
		recs = append(recs, res.rec)
	}

	return recs, quickErrCount, fullErrCount, walkErrCount, fileCount, nil
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

func quickDigestFile(path string, size int64, sampleBytes int64) ([32]byte, error) {
	// If disabled, fall back to full hashing.
	if sampleBytes <= 0 {
		return sha256File(path)
	}
	if size <= 0 {
		// Empty (or weird negative) file: no need to read from disk.
		return sha256.Sum256(nil), nil
	}

	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	// We hash up to 3 samples: start, middle, end.
	// This avoids reading tens of GiB for non-duplicates while still being very
	// effective at filtering.
	h := sha256.New()

	readAt := func(off int64, n int64) error {
		if off < 0 {
			off = 0
		}
		if off > size {
			off = size
		}
		if n < 0 {
			n = 0
		}
		if off+n > size {
			n = size - off
		}
		if n <= 0 {
			return nil
		}

		buf := make([]byte, n)
		_, err := f.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			return err
		}
		_, _ = h.Write(buf)
		return nil
	}

	n := sampleBytes
	if n > size {
		n = size
	}

	// Start
	if err := readAt(0, n); err != nil {
		return [32]byte{}, err
	}
	// Middle
	if size > n {
		mid := (size / 2) - (n / 2)
		if err := readAt(mid, n); err != nil {
			return [32]byte{}, err
		}
	}
	// End
	if size > n {
		end := size - n
		if err := readAt(end, n); err != nil {
			return [32]byte{}, err
		}
	}

	sum := h.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out, nil
}

func lessSum(a, b [32]byte) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			continue
		}
		return a[i] < b[i]
	}
	return false
}

func printDuplicateGroups(recs []hashedRec) (dupGroups int) {
	var (
		curSize     int64 = -1
		curHash     [32]byte
		curCount    int64
		firstPath   string
		groupActive bool
	)

	flush := func() {
		if groupActive {
			fmt.Println()
		}
		curSize = -1
		curHash = [32]byte{}
		curCount = 0
		firstPath = ""
		groupActive = false
	}

	for _, rec := range recs {
		if curCount == 0 {
			curSize = rec.size
			curHash = rec.sum
		}
		if rec.size != curSize || rec.sum != curHash {
			flush()
			curSize = rec.size
			curHash = rec.sum
		}

		curCount++
		if curCount == 1 {
			firstPath = rec.path
			continue
		}
		if curCount == 2 {
			dupGroups++
			fmt.Printf("Duplicate group (size=%d bytes, sha256=%s):\n", curSize, hex.EncodeToString(curHash[:]))
			fmt.Printf("  %s\n", firstPath)
			fmt.Printf("  %s\n", rec.path)
			groupActive = true
			continue
		}
		if groupActive {
			fmt.Printf("  %s\n", rec.path)
		}
	}

	if groupActive {
		fmt.Println()
	}
	return dupGroups
}
