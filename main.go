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
	flag.Parse()

	if err := run(*root, *workers); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, workers int) error {
	if workers < 1 {
		workers = 1
	}

	sizeCounts, walkErrCount, fileCount, err := countFileSizes(root)
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

	recs, hashErrCount, walkErrCount2, err := hashCandidates(root, sizeCounts, workers)
	if err != nil {
		return err
	}
	if walkErrCount2 > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while hashing-walk\n", walkErrCount2)
	}
	if hashErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while hashing\n", hashErrCount)
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

// ---- Pass 1: count file sizes ----

func countFileSizes(root string) (sizeCounts map[int64]uint32, walkErrCount int64, fileCount int64, _ error) {
	sizeCounts = make(map[int64]uint32, 1024)

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

		sz := info.Size()
		if sz < 0 {
			sz = 0
		}

		c := sizeCounts[sz]
		if c < ^uint32(0) {
			sizeCounts[sz] = c + 1
		}
		fileCount++
		return nil
	}

	if err := filepath.WalkDir(root, walkFn); err != nil {
		return nil, walkErrCount + 1, fileCount, fmt.Errorf("walk fatal error: %w", err)
	}
	return sizeCounts, walkErrCount, fileCount, nil
}

// ---- Pass 2: hash only sizes that occur > 1 ----

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

func hashCandidates(root string, sizeCounts map[int64]uint32, workers int) (recs []hashedRec, hashErrCount int64, walkErrCount int64, _ error) {
	if workers < 1 {
		workers = 1
	}

	jobCh := make(chan fileJob, 4096)
	resCh := make(chan hashResult, 4096)

	var workerWg sync.WaitGroup
	workerWg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer workerWg.Done()
			for job := range jobCh {
				sum, err := sha256File(job.path)
				resCh <- hashResult{
					rec: hashedRec{size: job.size, sum: sum, path: job.path},
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

			if sizeCounts[sz] > 1 {
				jobCh <- fileJob{path: path, size: sz}
			}
			return nil
		}

		walkFatalErr = filepath.WalkDir(root, walkFn)
		close(jobCh)
	}()

	go func() {
		workerWg.Wait()
		close(resCh)
	}()

	for res := range resCh {
		if res.err != nil {
			hashErrCount++
			fmt.Fprintf(os.Stderr, "hash error: %s: %v\n", res.rec.path, res.err)
			continue
		}
		recs = append(recs, res.rec)
	}

	walkWg.Wait()
	if walkFatalErr != nil {
		return nil, hashErrCount, walkErrCount, fmt.Errorf("walk fatal error: %w", walkFatalErr)
	}

	return recs, hashErrCount, walkErrCount, nil
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
