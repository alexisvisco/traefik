package redirect

import (
	"bytes"
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

var crawlers = regexp.MustCompile("baiduspider|twitterbot|facebookexternalhit|rogerbot|linkedinbot|embedly|quora link preview|showyoubot|outbrain|pinterest|slackbot|vkShare|W3C_Validator|googlebot|bingbot|discordbot|whatsapp")
var exceptions = regexp.MustCompile("\\.(js|css|xml|less|png|jpg|jpeg|gif|pdf|doc|txt|ico|rss|zip|mp3|rar|exe|wmv|doc|avi|ppt|mpg|mpeg|tif|wav|mov|psd|ai|xls|mp4|m4a|swf|dat|dmg|iso|flv|m4v|torrent|ttf|woff|svg|eot)$")

type RedirectRendertron struct {
	next       http.Handler
	errHandler utils.ErrorHandler
	name       string
	config     dynamic.RedirectRendertron
}

func NewRedirectRendertron(next http.Handler, name string, config dynamic.RedirectRendertron) (*RedirectRendertron, error) {

	logger := log.FromContext(middlewares.GetLoggerCtx(context.Background(), name, typeRendertronName))
	logger.Debug("Creating middleware")

	if config.ServiceName == "" {
		config.ServiceName = "frontend"
	}

	return &RedirectRendertron{next: next, errHandler: utils.DefaultHandler, name: name, config: config}, nil
}

func (r RedirectRendertron) GetTracingInformation() (name string, spanKind ext.SpanKindEnum) {
	return r.name, tracing.SpanKindNoneEnum
}

func (r *RedirectRendertron) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	userAgent := req.Header.Get("User-Agent")
	rawUrl := rawURL(req)
	logrus.
		WithField("user-agent", userAgent).
		WithField("match-user-agent", crawlers.MatchString(userAgent)).
		WithField("is-not-exception", !exceptions.MatchString(rawUrl)).
		Info("rendertron is alive")

	if crawlers.MatchString(userAgent) && !exceptions.MatchString(rawUrl) {

		rendertronUrl := "http://rendertron:3000/render/http://" + r.config.ServiceName + req.RequestURI

		buf := bytes.NewBufferString("")
		request, err := http.NewRequest("GET", rendertronUrl, buf)

		if err != nil {
			logrus.WithError(err).Info("rendertron is 0")
			r.errHandler.ServeHTTP(rw, req, err)
			return
		}
		defer request.Body.Close()

		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			logrus.WithError(err).Info("rendertron is 1")
			r.errHandler.ServeHTTP(rw, req, err)
			return
		}

		logrus.
			WithField("middleware", r.name).
			WithField("response-body", string(b)).
			WithField("user-agent", userAgent).Info(rendertronUrl)
		_, err = rw.Write(b)

		if err != nil {
			logrus.WithError(err).Info("rendertron is 2")
			r.errHandler.ServeHTTP(rw, req, err)
			return
		}

		r.next.ServeHTTP(rw, req)
	} else {
		r.next.ServeHTTP(rw, req)
	}
}
