package main

import(
	"fastjson_scan/src"
	"fmt"
	"time"
)

func main() {
	t1 := time.Now() // get current time
	var Info src.ScanInfo
	src.Flag(&Info)
	src.Scan(&Info)
	elapsed := time.Since(t1)
	fmt.Println("\nApp elapsed: ", elapsed)
}