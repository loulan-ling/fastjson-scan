package src

import (
	"flag"
	"fmt"
)


func Banner() {
	banner := `                     
##                   
 #   #               
 #                   
 #  ##  ####    #### 
 #   #   #  #  #  #  
 #   #   #  #  # ##  
 #   #   #  #   #    
### ### ### ##  #### 
               #   # 
                ###  `
	print(banner)
	fmt.Println("Version: 1.0")
}

func Flag(Info *ScanInfo) {
	Banner()
	flag.StringVar(&Info.Url, "u", "", "http://192.168.1.1:80")
	flag.StringVar(&Info.UrlFile, "f", "", "url.txt")
	flag.IntVar(&Info.Thread, "t", 10,"Thread default 10" )
	flag.Parse()
}
