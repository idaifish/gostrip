package internal

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"log"
)

func getPclntabFromELF(raw []byte) (uint64, uint64, binary.ByteOrder) {
	elfFile, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		log.Fatalf("Input file is not ELF format.")
	}

	if pclntabSection := elfFile.Section(".gopclntab"); pclntabSection != nil {
		return pclntabSection.Offset, pclntabSection.Size, elfFile.ByteOrder
	} else {
		log.Fatal("Failed to find .gopclntab section.")
	}

	return 0, 0, binary.LittleEndian
}
