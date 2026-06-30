package riskcontrol

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
)

const jsonlScannerBufferLimit = 4 << 20

func scanJSONLFile(path string, fn func([]byte) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, jsonlScannerBufferLimit)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func readLastNonEmptyLine(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 {
		return nil, nil
	}

	const chunkSize int64 = 4096
	var collected []byte
	for offset := info.Size(); offset > 0; {
		readSize := chunkSize
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		chunk := make([]byte, readSize)
		n, err := file.ReadAt(chunk, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		chunk = chunk[:n]
		collected = append(chunk, collected...)

		lines := bytes.Split(collected, []byte{'\n'})
		for i := len(lines) - 1; i >= 0; i-- {
			line := bytes.TrimSpace(lines[i])
			if len(line) == 0 {
				continue
			}
			if i == 0 && offset > 0 {
				break
			}
			return append([]byte(nil), line...), nil
		}
	}

	line := bytes.TrimSpace(collected)
	if len(line) == 0 {
		return nil, nil
	}
	return append([]byte(nil), line...), nil
}

func readTrimmedFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\ufeff")))
	if len(data) == 0 {
		return nil, nil
	}
	return append([]byte(nil), data...), nil
}
