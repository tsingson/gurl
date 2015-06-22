
package httpclient

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//******************************************************************************
//  type define
//******************************************************************************

// GurlHttpSettings
type GurlHttpSettings struct {
	ShowDebug        bool
	UserAgent        string
	ConnectTimeout   time.Duration
	ReadWriteTimeout time.Duration
	TlsClientConfig  *tls.Config
	Proxy            func(*http.Request) (*url.URL, error)
	Transport        http.RoundTripper
	EnableCookie     bool
	Gzip             bool
	DumpBody         bool
}

// GurlHttpRequest provides more useful methods for requesting one url than http.Request.
type GurlHttpRequest struct {
	url     string
	req     *http.Request
	params  map[string]string
	files   map[string]string
	setting GurlHttpSettings
	resp    *http.Response
	body    []byte
	dump    []byte
}

//******************************************************************************
//  function define
//******************************************************************************

// get request
func (r *GurlHttpRequest) GetRequest() *http.Request {
	return r.req
}

// Change request settings
func (r *GurlHttpRequest) Setting(setting GurlHttpSettings) *GurlHttpRequest {
	r.setting = setting
	return r
}

// SetBasicAuth sets the request's Authorization header to use HTTP Basic Authentication with the provided username and password.
func (r *GurlHttpRequest) SetBasicAuth(username, password string) *GurlHttpRequest {
	r.req.SetBasicAuth(username, password)
	return r
}

// SetEnableCookie sets enable/disable cookiejar
func (r *GurlHttpRequest) SetEnableCookie(enable bool) *GurlHttpRequest {
	r.setting.EnableCookie = enable
	return r
}

// SetUserAgent sets User-Agent header field
func (r *GurlHttpRequest) SetUserAgent(useragent string) *GurlHttpRequest {
	r.setting.UserAgent = useragent
	return r
}

// Debug sets show debug or not when executing request.
func (r *GurlHttpRequest) Debug(isdebug bool) *GurlHttpRequest {
	r.setting.ShowDebug = isdebug
	return r
}

// Dump Body.
func (r *GurlHttpRequest) DumpBody(isdump bool) *GurlHttpRequest {
	r.setting.DumpBody = isdump
	return r
}

// return the DumpRequest
func (r *GurlHttpRequest) DumpRequest() []byte {
	return r.dump
}

// SetTimeout sets connect time out and read-write time out for GurlRequest.
func (r *GurlHttpRequest) SetTimeout(connectTimeout, readWriteTimeout time.Duration) *GurlHttpRequest {
	r.setting.ConnectTimeout = connectTimeout
	r.setting.ReadWriteTimeout = readWriteTimeout
	return r
}

// SetTLSClientConfig sets tls connection configurations if visiting https url.
func (r *GurlHttpRequest) SetTLSClientConfig(config *tls.Config) *GurlHttpRequest {
	r.setting.TlsClientConfig = config
	return r
}

// Header add header item string in request.
func (r *GurlHttpRequest) Header(key, value string) *GurlHttpRequest {
	r.req.Header.Set(key, value)
	return r
}

// Set HOST
func (r *GurlHttpRequest) SetHost(host string) *GurlHttpRequest {
	r.req.Host = host
	return r
}

// Set the protocol version for incoming requests.
// Client requests always use HTTP/1.1.
func (r *GurlHttpRequest) SetProtocolVersion(vers string) *GurlHttpRequest {
	if len(vers) == 0 {
		vers = "HTTP/1.1"
	}

	major, minor, ok := http.ParseHTTPVersion(vers)
	if ok {
		r.req.Proto = vers
		r.req.ProtoMajor = major
		r.req.ProtoMinor = minor
	}

	return r
}

// SetCookie add cookie into request.
func (r *GurlHttpRequest) SetCookie(cookie *http.Cookie) *GurlHttpRequest {
	r.req.Header.Add("Cookie", cookie.String())
	return r
}

// Set transport to
func (r *GurlHttpRequest) SetTransport(transport http.RoundTripper) *GurlHttpRequest {
	r.setting.Transport = transport
	return r
}

// Set http proxy
// example:
//
//	func(req *http.Request) (*url.URL, error) {
// 		u, _ := url.ParseRequestURI("http://127.0.0.1:8118")
// 		return u, nil
// 	}
func (r *GurlHttpRequest) SetProxy(proxy func(*http.Request) (*url.URL, error)) *GurlHttpRequest {
	r.setting.Proxy = proxy
	return r
}

// Param adds query param in to request.
// params build query string as ?key1=value1&key2=value2...
func (r *GurlHttpRequest) Param(key, value string) *GurlHttpRequest {
	r.params[key] = value
	return r
}

func (r *GurlHttpRequest) PostFile(formname, filename string) *GurlHttpRequest {
	r.files[formname] = filename
	return r
}

// Body adds request raw body.
// it supports string and []byte.
func (r *GurlHttpRequest) Body(data interface{}) *GurlHttpRequest {
	switch t := data.(type) {
	case string:
		bf := bytes.NewBufferString(t)
		r.req.Body = ioutil.NopCloser(bf)
		r.req.ContentLength = int64(len(t))
	case []byte:
		bf := bytes.NewBuffer(t)
		r.req.Body = ioutil.NopCloser(bf)
		r.req.ContentLength = int64(len(t))
	}
	return r
}

// JsonBody adds request raw body encoding by JSON.
func (r *GurlHttpRequest) JsonBody(obj interface{}) (*GurlHttpRequest, error) {
	if r.req.Body == nil && obj != nil {
		buf := bytes.NewBuffer(nil)
		enc := json.NewEncoder(buf)
		if err := enc.Encode(obj); err != nil {
			return r, err
		}
		r.req.Body = ioutil.NopCloser(buf)
		r.req.ContentLength = int64(buf.Len())
		r.req.Header.Set("Content-Type", "application/json")
	}
	return r, nil
}

func (r *GurlHttpRequest) buildUrl(paramBody string) {
	// build GET url with query string
	if r.req.Method == "GET" && len(paramBody) > 0 {
		if strings.Index(r.url, "?") != -1 {
			r.url += "&" + paramBody
		} else {
			r.url = r.url + "?" + paramBody
		}
		return
	}

	// build POST/PUT/PATCH url and body
	if (r.req.Method == "POST" || r.req.Method == "PUT" || r.req.Method == "PATCH") && r.req.Body == nil {
		// with files
		if len(r.files) > 0 {
			pr, pw := io.Pipe()
			bodyWriter := multipart.NewWriter(pw)
			go func() {
				for formname, filename := range r.files {
					fileWriter, err := bodyWriter.CreateFormFile(formname, filename)
					if err != nil {
						log.Fatal(err)
					}
					fh, err := os.Open(filename)
					if err != nil {
						log.Fatal(err)
					}
					//iocopy
					_, err = io.Copy(fileWriter, fh)
					fh.Close()
					if err != nil {
						log.Fatal(err)
					}
				}
				for k, v := range r.params {
					bodyWriter.WriteField(k, v)
				}
				bodyWriter.Close()
				pw.Close()
			}()
			r.Header("Content-Type", bodyWriter.FormDataContentType())
			r.req.Body = ioutil.NopCloser(pr)
			return
		}

		// with params
		if len(paramBody) > 0 {
			r.Header("Content-Type", "application/x-www-form-urlencoded")
			r.Body(paramBody)
		}
	}
}

func (r *GurlHttpRequest) getResponse() (*http.Response, error) {
	if r.resp.StatusCode != 0 {
		return r.resp, nil
	}
	resp, err := r.SendOut()
	if err != nil {
		return nil, err
	}
	r.resp = resp
	return resp, nil
}

func (r *GurlHttpRequest) SendOut() (*http.Response, error) {
	var paramBody string
	if len(r.params) > 0 {
		var buf bytes.Buffer
		for k, v := range r.params {
			buf.WriteString(url.QueryEscape(k))
			buf.WriteByte('=')
			buf.WriteString(url.QueryEscape(v))
			buf.WriteByte('&')
		}
		paramBody = buf.String()
		paramBody = paramBody[0 : len(paramBody)-1]
	}

	r.buildUrl(paramBody)
	url, err := url.Parse(r.url)
	if err != nil {
		return nil, err
	}

	r.req.URL = url

	trans := r.setting.Transport

	if trans == nil {
		// create default transport
		trans = &http.Transport{
			TLSClientConfig: r.setting.TlsClientConfig,
			Proxy:           r.setting.Proxy,
			Dial:            TimeoutDialer(r.setting.ConnectTimeout, r.setting.ReadWriteTimeout),
		}
	} else {
		// if r.transport is *http.Transport then set the settings.
		if t, ok := trans.(*http.Transport); ok {
			if t.TLSClientConfig == nil {
				t.TLSClientConfig = r.setting.TlsClientConfig
			}
			if t.Proxy == nil {
				t.Proxy = r.setting.Proxy
			}
			if t.Dial == nil {
				t.Dial = TimeoutDialer(r.setting.ConnectTimeout, r.setting.ReadWriteTimeout)
			}
		}
	}

	var jar http.CookieJar = nil
	if r.setting.EnableCookie {
		if defaultCookieJar == nil {
			createDefaultCookie()
		}
		jar = defaultCookieJar
	}

	client := &http.Client{
		Transport: trans,
		Jar:       jar,
	}

	if r.setting.UserAgent != "" && r.req.Header.Get("User-Agent") == "" {
		r.req.Header.Set("User-Agent", r.setting.UserAgent)
	}

	if r.setting.ShowDebug {
		dump, err := httputil.DumpRequest(r.req, r.setting.DumpBody)
		if err != nil {
			println(err.Error())
		}
		r.dump = dump
	}
	return client.Do(r.req)
}

// String returns the body string in response.
// it calls Response inner.
func (r *GurlHttpRequest) String() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Bytes returns the body []byte in response.
// it calls Response inner.
func (r *GurlHttpRequest) Bytes() ([]byte, error) {
	if r.body != nil {
		return r.body, nil
	}
	resp, err := r.getResponse()
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if r.setting.Gzip && resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		r.body, err = ioutil.ReadAll(reader)
	} else {
		r.body, err = ioutil.ReadAll(resp.Body)
	}
	if err != nil {
		return nil, err
	}
	return r.body, nil
}

// ToFile saves the body data in response to one file.
// it calls Response inner.
func (r *GurlHttpRequest) ToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := r.getResponse()
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return nil
	}
	defer resp.Body.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// ToJson returns the map that marshals from the body bytes as json in response .
// it calls Response inner.
func (r *GurlHttpRequest) ToJson(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ToXml returns the map that marshals from the body bytes as xml in response .
// it calls Response inner.
func (r *GurlHttpRequest) ToXml(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, v)
}

// Response executes request client gets response mannually.
func (r *GurlHttpRequest) Response() (*http.Response, error) {
	return r.getResponse()
}

// TimeoutDialer returns functions of connection dialer with timeout settings for http.Transport Dial field.
func TimeoutDialer(cTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, nil
	}
}
//*****************************************************************************
var defaultSetting = GurlHttpSettings{false, "GurlServer", 60 * time.Second, 60 * time.Second, nil, nil, nil, false, true, true}
var defaultCookieJar http.CookieJar
var settingMutex sync.Mutex

// createDefaultCookie creates a global cookiejar to store cookies.
func createDefaultCookie() {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultCookieJar, _ = cookiejar.New(nil)
}

// Overwrite default settings
func SetDefaultSetting(setting GurlHttpSettings) {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultSetting = setting
	if defaultSetting.ConnectTimeout == 0 {
		defaultSetting.ConnectTimeout = 60 * time.Second
	}
	if defaultSetting.ReadWriteTimeout == 0 {
		defaultSetting.ReadWriteTimeout = 60 * time.Second
	}
}

// return *GurlHttpRequest with specific method
func NewGurlRequest(rawurl, method string) *GurlHttpRequest {
	var resp http.Response
	u, err := url.Parse(rawurl)
	if err != nil {
		log.Fatal(err)
	}
	req := http.Request{
		URL:        u,
		Method:     method,
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	return &GurlHttpRequest{rawurl, &req, map[string]string{}, map[string]string{}, defaultSetting, &resp, nil, nil}
}

// Get returns *GurlHttpRequest with GET method.
func Get(url string) *GurlHttpRequest {
	return NewGurlRequest(url, "GET")
}

// Post returns *GurlHttpRequest with POST method.
func Post(url string) *GurlHttpRequest {
	return NewGurlRequest(url, "POST")
}

// Put returns *GurlHttpRequest with PUT method.
func Put(url string) *GurlHttpRequest {
	return NewGurlRequest(url, "PUT")
}

// Delete returns *GurlHttpRequest DELETE method.
func Delete(url string) *GurlHttpRequest {
	return NewGurlRequest(url, "DELETE")
}

// Head returns *GurlHttpRequest with HEAD method.
func Head(url string) *GurlHttpRequest {
	return NewGurlRequest(url, "HEAD")
}
