
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const version = "v0.0.1 20150618"

var (
	ver              bool
	form             bool
	pretty           bool
	download         bool
	insecureSSL      bool
	auth             string
	proxy            string
	printV           string
	body             string
	bench            bool
	benchN           int
	benchC           int
	isjson           = flag.Bool("json", true, "Send the data as a JSON object")
	method           = flag.String("method", "GET", "HTTP method")
	URL              = flag.String("url", "", "HTTP request URL")
	jsonmap          map[string]interface{}
	contentJsonRegex = `application/json`
)

func init() {
	flag.BoolVar(&ver, "v", false, "Print Version Number")
	flag.BoolVar(&ver, "version", false, "Print Version Number")
	flag.BoolVar(&pretty, "pretty", true, "Print Json Pretty Fomat")
	flag.BoolVar(&pretty, "p", true, "Print Json Pretty Fomat")
	flag.StringVar(&printV, "print", "A", "Print request and response")
	flag.BoolVar(&form, "form", false, "Submitting as a form")
	flag.BoolVar(&form, "f", false, "Submitting as a form")
	flag.BoolVar(&download, "download", false, "Download the url content as file")
	flag.BoolVar(&download, "d", false, "Download the url content as file")
	flag.BoolVar(&insecureSSL, "insecure", false, "Allow connections to SSL sites without certs")
	flag.BoolVar(&insecureSSL, "i", false, "Allow connections to SSL sites without certs")
	flag.StringVar(&auth, "auth", "", "HTTP authentication username:password, USER[:PASS]")
	flag.StringVar(&auth, "a", "", "HTTP authentication username:password, USER[:PASS]")
	flag.StringVar(&proxy, "proxy", "", "Proxy host and port, PROXY_URL")
	flag.BoolVar(&bench, "bench", false, "Sends bench requests to URL")
	flag.BoolVar(&bench, "b", false, "Sends bench requests to URL")
	flag.IntVar(&benchN, "b.N", 1000, "Number of requests to run")
	flag.IntVar(&benchC, "b.C", 100, "Number of requests to run concurrently.")
	flag.StringVar(&body, "body", "", "Raw data send as body")
	jsonmap = make(map[string]interface{})
}

func main() {
	// bench run use multiple core or CPU
		runtime.GOMAXPROCS(runtime.NumCPU()*2)





	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) > 0 {
		args = filter(args)
	}
	if ver {
		fmt.Println("Version:", version)
		os.Exit(2)
	}
	if printV != "A" && printV != "B" {
		defaultSetting.DumpBody = false
	}
	var stdin []byte
	if runtime.GOOS != "windows" {
		fi, err := os.Stdin.Stat()
		if err != nil {
			panic(err)
		}
		if fi.Size() != 0 {
			stdin, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				log.Fatal("Read from Stdin", err)
			}
		}
	}

	if *URL == "" {
		usage()
	}
	if strings.HasPrefix(*URL, ":") {
		urlb := []byte(*URL)
		if *URL == ":" {
			*URL = "http://localhost/"
		} else if len(*URL) > 1 && urlb[1] != '/' {
			*URL = "http://localhost" + *URL
		} else {
			*URL = "http://localhost" + string(urlb[1:])
		}
	}
	if !strings.HasPrefix(*URL, "http://") && !strings.HasPrefix(*URL, "https://") {
		*URL = "http://" + *URL
	}
	u, err := url.Parse(*URL)
	if err != nil {
		log.Fatal(err)
	}
	if auth != "" {
		userpass := strings.Split(auth, ":")
		if len(userpass) == 2 {
			u.User = url.UserPassword(userpass[0], userpass[1])
		} else {
			u.User = url.User(auth)
		}
	}
	*URL = u.String()
	httpreq := getHTTP(*method, *URL, args)
	if u.User != nil {
		password, _ := u.User.Password()
		httpreq.GetRequest().SetBasicAuth(u.User.Username(), password)
	}
	// Insecure SSL Support
	if insecureSSL {
		httpreq.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}
	// Proxy Support
	if proxy != "" {
		purl, err := url.Parse(proxy)
		if err != nil {
			log.Fatal("Proxy Url parse err", err)
		}
		httpreq.SetProxy(http.ProxyURL(purl))
	} else {
		eurl, err := http.ProxyFromEnvironment(httpreq.GetRequest())
		if err != nil {
			log.Fatal("Environment Proxy Url parse err", err)
		}
		httpreq.SetProxy(http.ProxyURL(eurl))
	}
	if body != "" {
		httpreq.Body(body)
	}
	if len(stdin) > 0 {
		var j interface{}
		d := json.NewDecoder(bytes.NewReader(stdin))
		d.UseNumber()
		err = d.Decode(&j)
		if err != nil {
			httpreq.Body(stdin)
		} else {
			httpreq.JsonBody(j)
		}
	}

	// AB bench
	if bench {
		httpreq.Debug(false)
		RunBench(httpreq)
		return
	}
	res, err := httpreq.Response()
	if err != nil {
		log.Fatalln("can't get the url", err)
	}

	// download file
	if download {
		var fl string
		if disposition := res.Header.Get("Content-Disposition"); disposition != "" {
			fls := strings.Split(disposition, ";")
			for _, f := range fls {
				f = strings.TrimSpace(f)
				if strings.HasPrefix(f, "filename=") {
					fl = strings.TrimLeft(f, "filename=")
				}
			}
		}
		if fl == "" {
			_, fl = filepath.Split(u.Path)
		}
		fd, err := os.OpenFile(fl, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			log.Fatal("can't create file", err)
		}
		if runtime.GOOS != "windows" {
			fmt.Println(Color(res.Proto, Magenta), Color(res.Status, Green))
			for k, v := range res.Header {
				fmt.Println(Color(k, Gray), ":", Color(strings.Join(v, " "), Blue))
			}
		} else {
			fmt.Println(res.Proto, res.Status)
			for k, v := range res.Header {
				fmt.Println(k, ":", strings.Join(v, " "))
			}
		}
		fmt.Println("")
		contentLength := res.Header.Get("Content-Length")
		var total int64
		if contentLength != "" {
			total, _ = strconv.ParseInt(contentLength, 10, 64)
		}
		fmt.Printf("Downloading to \"%s\"\n", fl)
		pb := NewProgressBar(total)
		pb.Start()
		multiWriter := io.MultiWriter(fd, pb)
		_, err = io.Copy(multiWriter, res.Body)
		if err != nil {
			log.Fatal("Can't Write the body into file", err)
		}
		pb.Finish()
		defer fd.Close()
		defer res.Body.Close()
		return
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stdout.Stat()
		if err != nil {
			panic(err)
		}
		if fi.Mode()&os.ModeDevice == os.ModeDevice {
			if printV == "A" || printV == "H" || printV == "B" {
				dump := httpreq.DumpRequest()
				if printV == "B" {
					dps := strings.Split(string(dump), "\n")
					for i, line := range dps {
						if len(strings.Trim(line, "\r\n ")) == 0 {
							dump = []byte(strings.Join(dps[i:], "\n"))
							break
						}
					}
				}
				fmt.Println(ColorfulRequest(string(dump)))
				fmt.Println("")
			}
			if printV == "A" || printV == "h" {
				fmt.Println(Color(res.Proto, Magenta), Color(res.Status, Green))
				for k, v := range res.Header {
					fmt.Println(Color(k, Gray), ":", Color(strings.Join(v, " "), Blue))
				}
				fmt.Println("")
			}
			if printV == "A" || printV == "b" {
				body := formatResponseBody(res, httpreq, pretty)
				fmt.Println(ColorfulResponse(body, res.Header.Get("Content-Type")))
			}
		} else {
			body := formatResponseBody(res, httpreq, pretty)
			_, err = os.Stdout.WriteString(body)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else {
		if printV == "A" || printV == "H" || printV == "B" {
			dump := httpreq.DumpRequest()
			if printV == "B" {
				dps := strings.Split(string(dump), "\n")
				for i, line := range dps {
					if len(strings.Trim(line, "\r\n ")) == 0 {
						dump = []byte(strings.Join(dps[i:], "\n"))
						break
					}
				}
			}
			fmt.Println(string(dump))
			fmt.Println("")
		}
		if printV == "A" || printV == "h" {
			fmt.Println(res.Proto, res.Status)
			for k, v := range res.Header {
				fmt.Println(k, ":", strings.Join(v, " "))
			}
			fmt.Println("")
		}
		if printV == "A" || printV == "b" {
			body := formatResponseBody(res, httpreq, pretty)
			fmt.Println(body)
		}
	}
}

var UsageInfoCn string = `gurl 是一个 golang 开发的类似 *nix 下的 curl 小工具.

用法:

	gurl  [指令标识] [请求方法] URL [数据项 [数据项]]

指令标识:
  -body=""                    设置 HTTP payload 的原始数据
  -f, -form=false             以 form 表单方式提交数据( 一般是 POST 请求)
  -j, -json=true               以 json 数据格式提交数据
  -p, -pretty=true            对 json 数据进行格式化打印
  -print="A"                  设置指定必须包含的显示信息，默认是显示全部
         "H" request headers
         "B" request body
         "h" response headers
         "b" response body
  -v, -version=true           显示版本信息

请求方法:
   gurl 默认以 GET (未设置请求数据) 或者 POST (附带请求数据) 进行 HTTP 访问，可以设置为 GET / POST / DELETE / PUT 等.

URL:
  访问地址 URL 必须设置. 默认模式是 http://,
  比如  github.com 或者 bing.com 都是可以的.

数据项:
    可以是下面任一格式:
    Query string   key=value
    Header         key:value
    Post data      key=value
    File upload    key@/path/file

示例:
GET:
gurl httpbin.org/ip

PUT:
gurl PUT example.org X-API-Token:123 name=John

POST:
gurl -form=true POST example.org hello=World

DELETE:
gurl DELETE example.org/todos/7

`

func usage() {
	fmt.Println(UsageInfoCn)
	os.Exit(2)
}
