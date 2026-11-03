// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

// FileStats says how WriteExt4File got the data of the host files: Cloned files had every
// byte shared with the image, Copied files had at least some copied.
type FileStats struct{ Cloned, Copied int }

// WriteExt4File writes the tree as an ext4 image to f, which must be empty, and which may
// be sparse afterwards. A File node with a Source takes its data from that host file:
// the writer shares the file's blocks with the image where the filesystem allows it, and
// copies them where it does not. free is the space in bytes that the image holds beyond
// the tree, for the guest to fill when it mounts the image read-write; it is left as a
// hole, as is every block of zeros. A zero mtime means DefaultMtime.
func (t *Tree) WriteExt4File(f *os.File, mtime time.Time, free int64) (FileStats, error) {
	if free < 0 || free > maxImage {
		return FileStats{}, fmt.Errorf("%w: free space of %d bytes", ErrTooLarge, free)
	}
	list, p, err := t.layout(mtime, uint32(free/blockSize))
	if err != nil {
		return FileStats{}, err
	}
	if err := f.Truncate(int64(p.blocks) * blockSize); err != nil {
		return FileStats{}, fmt.Errorf("rootfs: size the image: %w", err)
	}
	s := &fileSink{f: f, copied: map[*HostFile]bool{}}
	if err := p.emit(s, list); err != nil {
		return FileStats{}, fmt.Errorf("rootfs: write image: %w", err)
	}
	var st FileStats
	for _, copied := range s.copied {
		if copied {
			st.Copied++
		} else {
			st.Cloned++
		}
	}
	return st, nil
}

// fileSink is the sink of WriteExt4File: it writes at pos, and leaves zeros as holes.
type fileSink struct {
	f      *os.File
	pos    int64
	copied map[*HostFile]bool // per host file, whether any run of it was copied
}

func (s *fileSink) skip(n int64) error { s.pos += n; return nil }

// put writes b, except for the blocks of zeros in it.
func (s *fileSink) put(b []byte) error {
	start := -1 // the start of the run of nonzero blocks being collected
	write := func(end int) error {
		if start < 0 {
			return nil
		}
		_, err := s.f.WriteAt(b[start:end], s.pos+int64(start))
		start = -1
		return err
	}
	for i := 0; i < len(b); i += blockSize {
		if end := min(i+blockSize, len(b)); !bytes.Equal(b[i:end], zeros[:end-i]) {
			if start < 0 {
				start = i
			}
		} else if err := write(i); err != nil {
			return err
		}
	}
	if err := write(len(b)); err != nil {
		return err
	}
	s.pos += int64(len(b))
	return nil
}

// file puts the run's data in place: shared if it can be, else copied.
func (s *fileSink) file(g seg) error {
	n := min(int64(g.n)*blockSize, g.src.Size-g.off)
	src, err := openSource(g.src)
	if err != nil {
		return err
	}
	defer src.Close()
	copied := cloneRange(s.f, src, g.off, n, s.pos) != nil
	if copied {
		if _, err := src.Seek(g.off, io.SeekStart); err != nil {
			return err
		}
		if _, err := s.f.Seek(s.pos, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(s.f, src, n); err != nil {
			return fmt.Errorf("copy %s: %w", g.src.Path, err)
		}
	}
	s.copied[g.src] = s.copied[g.src] || copied
	s.pos += int64(g.n) * blockSize
	return nil
}

// openSource opens the host file for reading and checks that it is the file the caller saw.
func openSource(h *HostFile) (*os.File, error) {
	// O_NONBLOCK so that a file swapped for a FIFO cannot hold the open.
	f, err := os.OpenFile(h.Path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || !fi.Mode().IsRegular() || uint64(st.Dev) != h.Dev || uint64(st.Ino) != h.Ino || fi.Size() != h.Size {
			err = fmt.Errorf("%s changed while the image was written", h.Path)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
