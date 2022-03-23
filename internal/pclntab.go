package internal

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"log"
)

var pclntabMagic = []byte{0xfa, 0xff, 0xff, 0xff, 0x00, 0x00}

func getPclntab(raw []byte) (uint64, uint64, binary.ByteOrder) {
	switch {
	case bytes.HasPrefix(raw, []byte(elf.ELFMAG)) == true:
		return getPclntabFromELF(raw)
	case bytes.HasPrefix(raw, []byte{0xcf, 0xfa, 0xed, 0xfe}) == true:
		return getPclntabFromMacho(raw)
	case bytes.HasPrefix(raw, []byte{0xca, 0xfe, 0xba, 0xbe}) == true:
		return getPclntabFromFatMacho(raw)
	case bytes.HasPrefix(raw, []byte{0x4d, 0x5a}) == true:
		return getPclntabFromPE(raw)
	default:
		log.Fatal("File format is not supported.")
	}

	return 0, 0, binary.LittleEndian
}

func getPclntabFromELF(raw []byte) (uint64, uint64, binary.ByteOrder) {
	elfFile, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		log.Fatal("Input file is not ELF format.")
	}

	if pclntabSection := elfFile.Section(".gopclntab"); pclntabSection != nil {
		return pclntabSection.Offset, pclntabSection.Size, elfFile.ByteOrder
	}

	// PIE or CGO
	dataSection := elfFile.Section(".data.rel.ro")
	if dataSection != nil {
		data, err := dataSection.Data()
		if err != nil {
			log.Fatal(err)
		}
		tabOffset := bytes.Index(data, pclntabMagic)
		if tabOffset != -1 {
			return dataSection.Offset + uint64(tabOffset), dataSection.Size - uint64(tabOffset), elfFile.ByteOrder
		}
	} else {
		log.Fatal("Failed to find pclntab.")
	}

	return 0, 0, binary.LittleEndian
}

func getPclntabFromMacho(raw []byte) (uint64, uint64, binary.ByteOrder) {
	machoFile, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		log.Fatal("Input file is not Mach-O format.")
	}

	if pclntabSection := machoFile.Section("__gopclntab"); pclntabSection != nil {
		return uint64(pclntabSection.Offset), pclntabSection.Size, machoFile.ByteOrder
	} else {
		log.Fatal("Failed to find pclntab.")
	}

	return 0, 0, binary.LittleEndian
}

func getPclntabFromFatMacho(raw []byte) (uint64, uint64, binary.ByteOrder) {
	fatFile, err := macho.NewFatFile(bytes.NewReader(raw))
	if err != nil {
		log.Fatal("Input file is not Fat Mach-O format.")
	}
	machoFile := fatFile.Arches[0]

	if pclntabSection := machoFile.Section("__gopclntab"); pclntabSection != nil {
		return uint64(pclntabSection.Offset), pclntabSection.Size, machoFile.ByteOrder
	} else {
		log.Fatal("Failed to find pclntab.")
	}

	return 0, 0, binary.LittleEndian
}

func getPclntabFromPE(raw []byte) (uint64, uint64, binary.ByteOrder) {
	peFile, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		log.Fatal("Input file is not PE format.")
	}

	dataSection := peFile.Section(".rdata")
	if dataSection != nil {
		data, err := dataSection.Data()
		if err != nil {
			log.Fatal(err)
		}
		tabOffset := bytes.Index(data, pclntabMagic)
		if tabOffset != -1 {
			return uint64(dataSection.Offset) + uint64(tabOffset), uint64(dataSection.Size) - uint64(tabOffset), binary.LittleEndian
		}
	} else {
		log.Fatal("Failed to find pclntab.")
	}

	return 0, 0, binary.LittleEndian
}
