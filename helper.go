package main

import "debug/elf"
import "debug/pe"
import "fmt"

type CaveInformation struct {
    typeOfFile string
    sectionName string
    sectionOffset string
    sectionSize string
    sectionFlags string
    virtAddress string
    caveStart string
    caveEnd string
    caveSize string
}

const CaveByte = 0x00

func CheckByte(b byte) bool {
    return b == CaveByte
}

func FindCaveElf(section *elf.Section, caveSize int) ([]CaveInformation, error) {
    sectionBody, err := section.Data()
    if err != nil {
        return nil, err
    }

    result := []CaveInformation{}

    count := 0

    for cursor := 0; cursor < len(sectionBody); cursor++ {
        b := sectionBody[cursor]
        if CheckByte(b) {
            count++
        } else {
            if count >= caveSize {
                caveInfo := CaveInformation{
                    "ELF",
                    fmt.Sprintf("%s", section.Name),
                    fmt.Sprintf("%#x", section.Offset),
                    fmt.Sprintf("%x (%d bytes)", section.Size, int(section.Size)),
                    fmt.Sprintf("%s", section.Flags.String()),
                    fmt.Sprintf("%#x", int(section.Addr) + cursor - count),
                    fmt.Sprintf("%#x", int(section.Offset) + cursor - count),
                    fmt.Sprintf("%#x", int(section.Offset) + cursor),
                    fmt.Sprintf("%#x (%d bytes)", count, int(count)),
                }
                result = append(result, caveInfo)
            }
            count = 0
        }
    }

    return result, nil
}

func FindCavePE(section *pe.Section, caveSize int) ([]CaveInformation, error) {
    sectionBody, err := section.Data()
    if err != nil {
        return nil, err
    }

    result := []CaveInformation{}

    count := 0

    for cursor := 0; cursor < len(sectionBody); cursor++ {
        b := sectionBody[cursor]
        if CheckByte(b) {
            count++
        } else {
	    if count >= caveSize {
                caveInfo := CaveInformation{
                    "PE",
                    fmt.Sprintf("%s", section.SectionHeader.Name),
                    fmt.Sprintf("%#x", section.SectionHeader.Offset),
                    fmt.Sprintf("%x (%d bytes)", section.SectionHeader.Size, int(section.SectionHeader.Size)),
                    fmt.Sprintf("%x", section.SectionHeader.Characteristics),
                    fmt.Sprintf("%#x", int(section.SectionHeader.VirtualAddress) + cursor - count),
                    fmt.Sprintf("%#x", int(section.SectionHeader.Offset) + cursor - count),
                    fmt.Sprintf("%#x", int(section.SectionHeader.Offset) + cursor),
                    fmt.Sprintf("%#x (%d bytes)", count, int(count)),
                }
                result = append(result, caveInfo)
            }
            count = 0
        }
    }

    return result, nil
}

func PrintCaveInfo(caveInfo CaveInformation) {
    fmt.Println("\n[+] CAVE DETECTED!")
    fmt.Printf("[!] File type: %s\n", caveInfo.typeOfFile)
	fmt.Printf("[!] Section Name: %s\n", caveInfo.sectionName)
	fmt.Printf("[!] Section Offset: %s\n", caveInfo.sectionOffset)
	fmt.Printf("[!] Section Size: %s\n", caveInfo.sectionSize)
	fmt.Printf("[!] Section Flags: %s\n", caveInfo.sectionFlags)
	fmt.Printf("[!] Virtual Address: %s\n", caveInfo.virtAddress)
	fmt.Printf("[!] Cave Begin: %s\n", caveInfo.caveStart)
	fmt.Printf("[!] Cave End: %s\n", caveInfo.caveEnd)
	fmt.Printf("[!] Cave Size: %s\n", caveInfo.caveSize)
}
