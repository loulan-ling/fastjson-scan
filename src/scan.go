package src

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

func Scan(Info *ScanInfo) {

	if Info.Url != ""{
		results := VerifyUrl(Info.Url)
		if results == true{
			Info.ScanUrl  = append(Info.ScanUrl,Info.Url)
		}
	}
	if Info.UrlFile !="" {
		fi, err := os.Open(Info.UrlFile)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		defer fi.Close()

		br := bufio.NewReader(fi)
		for {
			url, _, error := br.ReadLine()
			if error == io.EOF {
				break
			}
			results := VerifyUrl(string(url))
			if results == true{
				Info.ScanUrl  = append(Info.ScanUrl,string(url))
			}

		}
	}

	race(Info)


}


//Verify url
func VerifyUrl (Url  string )(bool){

	urlRegex := "^(https?://)[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]"
	match, err := regexp.MatchString(urlRegex, Url)
	if err !=nil{
		return false
	}

	return match

}


func race(Info *ScanInfo){
	cond :=sync.NewCond(&sync.Mutex{})
	var wg sync.WaitGroup
	//ScanUrl := make(chan string)
	wg.Add(len(Info.ScanUrl)+1)
	for i:=0;i<len(Info.ScanUrl); i++ {
		go func(num int) {
			defer  wg.Done()
			cond.L.Lock()
			cond.Wait()//等待发令枪响
			fmt.Printf("%s 扫描中\n",Info.ScanUrl[num])
		//	ScanUrl <- Info.ScanUrl[num]
			ScanResult:=WebRequest(Info.ScanUrl[num])
			if ScanResult==true{
				fmt.Printf("[+]%s 存在fastjson\n",Info.ScanUrl[num])
			}
			//fmt.Printf("%s号开始跑……",Info.ScanUrl[num])
			cond.L.Unlock()
		}(i)
	}
	//等待所有goroutine都进入wait状态
	time.Sleep(2*time.Second)
	go func() {
		defer  wg.Done()
		cond.Broadcast()//发令枪响
	}()
	//防止函数提前返回退出
	wg.Wait()
}

func WebRequest(Url string)(bool) {
	//http Request
	if strings.Contains(Url,"http://")==true{
		for i := 0; i < len(Payload); i++ {
			var jsonStr = []byte(Payload[i])
			req, err := http.NewRequest("POST", Url, bytes.NewBuffer(jsonStr))
			// req.Header.Set("X-Custom-Header", "myvalue")
			req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()

			//fmt.Println("response Status:", resp.Status)
			//fmt.Println("response Headers:", resp.Header)
			body, _ := ioutil.ReadAll(resp.Body)
			if strings.ContainsAny(string(body), "fastjson") == true && resp.StatusCode!=200 || strings.ContainsAny(string(body), "alibaba") == true && resp.StatusCode!=200 {
				return true
			}

			//fmt.Println("response Body:", string(body))

		}

		return false
	}

	//https Request
	if strings.Contains(Url,"https://") {
		timeout := time.Duration(1000 * time.Second) //time out
		client  := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		for i := 0; i < len(Payload); i++ {

			var jsonStr = []byte(Payload[i])
			req, err := http.NewRequest("POST", Url, bytes.NewBuffer(jsonStr))
			// req.Header.Set("X-Custom-Header", "myvalue")
			req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)

			if strings.ContainsAny(string(body), "fastjson") == true && resp.StatusCode!=200 || strings.ContainsAny(string(body), "alibaba") == true && resp.StatusCode!=200 {
				return true
			}

		}


	}
	return false
}



//func test(Url string){
//
//	fmt.Println(Url,1)
//}