package main

import(
	"fastjson_scan/src"

)

func main() {
	var Info src.ScanInfo
	src.Flag(&Info)
	src.Scan(&Info)

}