package main

import (
	"flag"
	"github.com/idaifish/gostrip/internal"
	"log"
)

var out = flag.String("o", "", "output file name. write in place by default.")

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 {
		log.Fatalln("Usage: gostrip [option] [executable file name]")
	}

	internal.Gostrip(flag.Args()[0], *out)
}
