# httpclient
httpclient is an libs help you to curl remote url.

# How to use?

## GET
you can use Get to crawl data.

	import "github.com/tsingson/gurl/httpclient"

	str, err := httpclient.Get("http://httpbin.org/").String()
	if err != nil {
        	// error
	}
	fmt.Println(str)

## POST
POST data to remote url

	req := httpclient.Post("http://httpbin.org/")
	req.Param("username","tsingson")
	req.Param("password","123456")
	str, err := req.String()
	if err != nil {
        	// error
	}
	fmt.Println(str)

## Set timeout

The default timeout is `60` seconds, function prototype:

	SetTimeout(connectTimeout, readWriteTimeout time.Duration)

Exmaple:

	// GET
	httpclient.Get("http://httpbin.org/").SetTimeout(100 * time.Second, 30 * time.Second)

	// POST
	httpclient.Post("http://httpbin.org/").SetTimeout(100 * time.Second, 30 * time.Second)


## Debug

If you want to debug the request info, set the debug on

	httpclient.Get("http://httpbin.org/").Debug(true)

## Set HTTP Basic Auth

	str, err := Get("http://httpbin.org/").SetBasicAuth("user", "passwd").String()
	if err != nil {
        	// error
	}
	fmt.Println(str)

## Set HTTPS

If request url is https, You can set the client support TSL:

	httpclient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

More info about the `tls.Config` please visit http://golang.org/pkg/crypto/tls/#Config

## Set HTTP Version

some servers need to specify the protocol version of HTTP

	httpclient.Get("http://httpbin.org/").SetProtocolVersion("HTTP/1.1")

## Set Cookie

some http request need setcookie. So set it like this:

	cookie := &http.Cookie{}
	cookie.Name = "username"
	cookie.Value  = "tsingson"
	httpclient.Get("http://httpbin.org/").SetCookie(cookie)

## Upload file

httpclient support mutil file upload, use `req.PostFile()`

	req := httpclient.Post("http://httpbin.org/")
	req.Param("username","tsingson")
	req.PostFile("uploadfile1", "httpclient.pdf")
	str, err := req.String()
	if err != nil {
        	// error
	}
	fmt.Println(str)


See godoc for further documentation and examples.

* [godoc.org/github.com/tsingson/gurl/httpclient](https://godoc.org/github.com/tsingson/gurl/httpclient)
