package redirect

import (
	"context"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/opentracing/opentracing-go/ext"
	"github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/utils"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares"
	"github.com/containous/traefik/v2/pkg/tracing"
)

const (
	typeRendertronName = "RedirectRendertron"
)

var defaultCrawlers = "baiduspider|Twitterbot|facebookexternalhit|rogerbot|linkedinbot|embedly|quora link preview|showyoubot|outbrain|pinterest|slackbot|vkShare|W3C_Validator|googlebot|bingbot|discordbot|whatsapp"
var defaultExceptions = "\\.(js|css|xml|less|png|jpg|jpeg|gif|pdf|doc|txt|ico|rss|zip|mp3|rar|exe|wmv|doc|avi|ppt|mpg|mpeg|tif|wav|mov|psd|ai|xls|mp4|m4a|swf|dat|dmg|iso|flv|m4v|torrent|ttf|woff|svg|eot)$"

type RedirectRendertron struct {
	next       http.Handler
	errHandler utils.ErrorHandler
	name       string

	config     dynamic.RedirectRendertron
	crawlers   *regexp.Regexp
	exceptions *regexp.Regexp
}

func NewRedirectRendertron(next http.Handler, name string, config dynamic.RedirectRendertron) (*RedirectRendertron, error) {

	logger := log.FromContext(middlewares.GetLoggerCtx(context.Background(), name, typeRendertronName))
	logger.Debug("Creating middleware")

	if config.ServiceName == "" {
		config.ServiceName = "frontend"
	}

	if config.Crawlers == "" {
		config.Crawlers = defaultCrawlers
	}

	if config.Exceptions == "" {
		config.Exceptions = defaultExceptions
	}

	r := &RedirectRendertron{next: next, errHandler: utils.DefaultHandler, name: name, config: config}

	var err error
	r.crawlers, err = regexp.Compile(config.Crawlers)
	if err != nil {
		return nil, err
	}

	r.exceptions, err = regexp.Compile(config.Exceptions)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r RedirectRendertron) GetTracingInformation() (name string, spanKind ext.SpanKindEnum) {
	return r.name, tracing.SpanKindNoneEnum
}

func (r *RedirectRendertron) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	userAgent := req.Header.Get("User-Agent")
	rawUrl := rawURL(req)

	if r.crawlers.MatchString(userAgent) && !r.exceptions.MatchString(rawUrl) {

		rendertronUrl := "http://rendertron:3000/render/http://" + r.config.ServiceName + req.RequestURI

		resp, err := http.Get(rendertronUrl)

		if err != nil {
			r.errHandler.ServeHTTP(rw, req, err)
			return
		}

		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			r.errHandler.ServeHTTP(rw, req, err)
			return
		}

		logrus.
			WithField("middleware", r.name).
			WithField("response-status", resp.Status).
			WithField("user-agent", userAgent).Info(rendertronUrl)

		_, err = rw.Write(b)

		if err != nil {
			r.errHandler.ServeHTTP(rw, req, err)
			return
		}

		return
	} else {
		r.next.ServeHTTP(rw, req)
	}
}
