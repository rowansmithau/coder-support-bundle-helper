package util

import (
	"archive/zip"
	"compress/gzip"
	"io"
)

const MaxGzipLayers = 5

// ReadZipFile reads the entire contents of a zip file entry.
// The caller does not need to close the returned bytes.
func ReadZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// ReadZipFileLimited reads up to limit bytes from a zip file entry.
// Returns the content, whether it was truncated, and any error.
func ReadZipFileLimited(f *zip.File, limit int64) ([]byte, bool, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()

	lr := io.LimitReader(rc, limit+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, false, err
	}
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	return data, truncated, nil
}

// DetectAndDecompressAll repeatedly decompresses gzip data up to MaxGzipLayers.
// Returns the decompressed data, number of layers decompressed, and any error.
func DetectAndDecompressAll(data []byte) ([]byte, int, error) {
	layers := 0
	for layers < MaxGzipLayers {
		if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
			break
		}
		gr, err := gzip.NewReader(io.NopCloser(io.LimitReader(
			bytesReader(data), int64(len(data)),
		)))
		if err != nil {
			break
		}
		decompressed, err := io.ReadAll(gr)
		_ = gr.Close()
		if err != nil {
			return nil, layers, err
		}
		data = decompressed
		layers++
	}
	return data, layers, nil
}

// bytesReader wraps a byte slice as an io.Reader
func bytesReader(data []byte) io.Reader {
	return &bytesReaderImpl{data: data}
}

type bytesReaderImpl struct {
	data []byte
	pos  int
}

func (r *bytesReaderImpl) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// FindSibling searches for a file with the given name in the zip reader.
func FindSibling(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}
