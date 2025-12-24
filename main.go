package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
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

	sizeToPaths, walkErrCount := collectFilesBySize(*root)
	if walkErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while walking\n", walkErrCount)
	}

	var jobs []fileJob
	for size, paths := range sizeToPaths {
		if len(paths) < 2 {
			continue
		}
		for _, p := range paths {
			jobs = append(jobs, fileJob{path: p, size: size})
		}
	}

	dups, hashErrCount := hashAndGroup(jobs, *workers)
	if hashErrCount > 0 {
		fmt.Fprintf(os.Stderr, "warning: encountered %d errors while hashing\n", hashErrCount)
	}

	printDuplicates(dups)
}

type fileJob struct {
	path string
	size int64
}

type hashResult struct {
	path string
	size int64
	sum  string
	err  error
}

func collectFilesBySize(root string) (map[int64][]string, int) {
	sizeToPaths := make(map[int64][]string)
	errCount := 0

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errCount++
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
			errCount++
			fmt.Fprintf(os.Stderr, "stat error: %s: %v\n", path, infoErr)
			return nil
		}

		sizeToPaths[info.Size()] = append(sizeToPaths[info.Size()], path)
		return nil
	}

	if err := filepath.WalkDir(root, walkFn); err != nil {
		// WalkDir only returns a terminal error (e.g., invalid root); per-file
		// errors are handled inside walkFn.
		errCount++
		fmt.Fprintf(os.Stderr, "walk fatal error: %v\n", err)
	}

	return sizeToPaths, errCount
}

func hashAndGroup(jobs []fileJob, workers int) (map[string][]string, int) {
	if workers < 1 {
		workers = 1
	}

	jobCh := make(chan fileJob)
	resCh := make(chan hashResult)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for job := range jobCh {
				sum, err := sha256File(job.path)
				resCh <- hashResult{
					path: job.path,
					size: job.size,
					sum:  sum,
					err:  err,
				}
			}
		}()
	}

	go func() {
		for _, j := range jobs {
			jobCh <- j
		}
		close(jobCh)
		wg.Wait()
		close(resCh)
	}()

	errCount := 0
	keyToPaths := make(map[string][]string)
	for res := range resCh {
		if res.err != nil {
			errCount++
			fmt.Fprintf(os.Stderr, "hash error: %s: %v\n", res.path, res.err)
			continue
		}
		// Include size to make output a bit more informative and avoid any
		// (theoretical) cross-size confusion.
		key := fmt.Sprintf("%d:%s", res.size, res.sum)
		keyToPaths[key] = append(keyToPaths[key], res.path)
	}

	// Keep only true duplicates.
	for k, paths := range keyToPaths {
		if len(paths) < 2 {
			delete(keyToPaths, k)
		}
	}

	return keyToPaths, errCount
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := copyBuffered(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyBuffered(dst hash.Hash, src *os.File) (int64, error) {
	// 1 MiB buffer: good throughput without being too memory-heavy.
	buf := make([]byte, 1024*1024)
	return io.CopyBuffer(dst, src, buf)
}

func printDuplicates(keyToPaths map[string][]string) {
	if len(keyToPaths) == 0 {
		fmt.Println("No duplicates found.")
		return
	}

	keys := make([]string, 0, len(keyToPaths))
	for k := range keyToPaths {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		paths := keyToPaths[k]
		sort.Strings(paths)

		size, sum := splitKey(k)
		fmt.Printf("Duplicate group (size=%s bytes, sha256=%s):\n", size, sum)
		for _, p := range paths {
			fmt.Printf("  %s\n", p)
		}
		fmt.Println()
	}
}

func splitKey(key string) (size string, sum string) {
	// key format: "<size>:<sha256hex>"
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return "?", key
}
