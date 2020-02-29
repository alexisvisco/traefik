package redirect

import (
	"net/http"
	"net/url"
	"regexp"

	"github.com/opentracing/opentracing-go/ext"
	"github.com/vulcand/oxy/utils"

	"github.com/containous/traefik/v2/pkg/tracing"
)

var crawlers = regexp.MustCompile("baiduspider|twitterbot|facebookexternalhit|rogerbot|linkedinbot|embedly|quora link preview|showyoubot|outbrain|pinterest|slackbot|vkShare|W3C_Validator|googlebot|bingbot|discordbot|whatsapp")
var exceptions = regexp.MustCompile("\\.(js|css|xml|less|png|jpg|jpeg|gif|pdf|doc|txt|ico|rss|zip|mp3|rar|exe|wmv|doc|avi|ppt|mpg|mpeg|tif|wav|mov|psd|ai|xls|mp4|m4a|swf|dat|dmg|iso|flv|m4v|torrent|ttf|woff|svg|eot)$")

type RedirectRendertron struct {
	next       http.Handler
	errHandler utils.ErrorHandler
	name       string
}

func NewRedirectRendertron(next http.Handler, name string) (*RedirectRendertron, error) {
	return &RedirectRendertron{next: next, errHandler: utils.DefaultHandler, name: name}, nil
}

func (r RedirectRendertron) GetTracingInformation() (name string, spanKind ext.SpanKindEnum) {
	return r.name, tracing.SpanKindNoneEnum
}

func (r *RedirectRendertron) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	userAgent := req.Header.Get("User-Agent")
	rawUrl := rawURL(req)

	if crawlers.MatchString(userAgent) && !exceptions.MatchString(rawUrl) {
		parsedUrl, err := url.Parse("http://rendertron/render/" + rawUrl)
		if err != nil {
			return
		}
		handler := moveHandler{
			location:  parsedUrl,
			permanent: false,
		}

		r.errHandler.ServeHTTP(rw, req, err)
		handler.ServeHTTP(rw, req)
	} else {
		r.next.ServeHTTP(rw, req)
	}
}
