package main

import "os"
import "fmt"
import "strconv"
import "debug/elf"
import "debug/pe"

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: cavefinder <elf/pe_file> <cave_size>\n")
		os.Exit(1)
	}

	file := os.Args[1]
	caveSize, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	elfFile, err := elf.Open(file)
	if err != nil {
        peFile, err := pe.Open(file)
        if err != nil {
            fmt.Printf("File is neither valid elf nor valid PE\n")
            os.Exit(3)
        } else {
            for _, section := range peFile.Sections {
                results, err := FindCavePE(section, caveSize)
                if err != nil {
                    fmt.Println(err)
                    os.Exit(4)
                }

                if len(results) > 1 {
                    for _, value := range results {
                        PrintCaveInfo(value)
                    }
                }
            }
        }
	} else {
		for _, section := range elfFile.Sections {
			results, err := FindCaveElf(section, caveSize)
			if err != nil {
				fmt.Println(err)
				os.Exit(5)
			}

			if len(results) > 1 {
                for _, value := range results {
                    PrintCaveInfo(value)
                }
			}
		}
	}
}
