package src

import (
	"flag"

)

func Flag(Info *ScanInfo) {

	flag.StringVar(&Info.Url, "u", "", "http://192.168.1.1:80")
	flag.StringVar(&Info.UrlFile, "f", "", "url.txt")
	flag.IntVar(&Info.Thread, "t", 10,"Thread default 10" )
	flag.Parse()

}
