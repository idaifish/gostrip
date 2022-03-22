package internal

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"os"
)

func Gostrip(in, out string) {
	inFile, err := os.Open(in)
	if err != nil {
		log.Fatalf("Can't open %s", in)
	}
	defer inFile.Close()

	raw, err := io.ReadAll(inFile)
	if err != nil {
		log.Fatalf("Can't read %s", in)
	}

	offset, size, byteOrder := getPclntabFromELF(raw)
	strip(raw, offset, size, byteOrder)

	if out == "" {
		out = in
	}

	err = os.WriteFile(out, raw, 0775)
	if err != nil {
		log.Fatalf("Can't write %s: %s", out, err)
	}
}

func strip(raw []byte, offset, size uint64, byteOrder binary.ByteOrder) {
	data := raw[offset : offset+size]

	ptrSize := data[7]
	uintPtr := func(b []byte) uint64 {
		if ptrSize == 4 {
			return uint64(byteOrder.Uint32(b))
		}
		return byteOrder.Uint64(b)
	}

	funcNameOffset := uintPtr(data[8+2*ptrSize:])
	funcNameTab := data[funcNameOffset:]

	fileTabOffset := uintPtr(data[8+4*ptrSize:])
	fileTab := data[fileTabOffset:]

	stripNames(fileTab)
	stripNames(funcNameTab)
}

func stripNames(tab []byte) {
	reader := bytes.NewReader(tab)
	lastOffset := int64(0)

	for {
		for {
			if b, err := reader.ReadByte(); err == nil {
				if b == 0 {
					break
				}
			} else {
				log.Fatal(err)
			}
		}

		if curOffset, err := reader.Seek(0, io.SeekCurrent); err == nil {
			if curOffset-1 == lastOffset {
				break
			}
			//log.Println(string(tab[lastOffset : curOffset-1]))
			for j := lastOffset; j < curOffset-1; j++ {
				tab[j] = '?'
			}
			lastOffset = curOffset
		} else {
			log.Fatal(err)
		}

	}
}