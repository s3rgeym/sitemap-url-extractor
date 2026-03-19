package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	LDEBUG = iota
	LINFO
	LWARN
	LERR
	MaxBodySize = 8 * 1024 * 1024

	// ANSI colors
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

type Logger struct {
	level int
}

func (l Logger) Debug(format string, args ...any) {
	if l.level <= LDEBUG {
		fmt.Fprintf(os.Stderr, colorCyan+"[DEBUG] "+format+colorReset+"\n", args...)
	}
}

func (l Logger) Info(format string, args ...any) {
	if l.level <= LINFO {
		fmt.Fprintf(os.Stderr, colorGreen+"[INFO]  "+format+colorReset+"\n", args...)
	}
}

func (l Logger) Warn(format string, args ...any) {
	if l.level <= LWARN {
		fmt.Fprintf(os.Stderr, colorYellow+"[WARN]  "+format+colorReset+"\n", args...)
	}
}

func (l Logger) Err(format string, args ...any) {
	if l.level <= LERR {
		fmt.Fprintf(os.Stderr, colorRed+"[ERR]   "+format+colorReset+"\n", args...)
	}
}

type Sitemap struct {
	Locations []string `xml:"url>loc"`
}

type SitemapIndex struct {
	Locations []string `xml:"sitemap>loc"`
}

type Scanner struct {
	inputFile       string
	outputFile      string
	workers         int
	connTimeout     time.Duration
	reqTimeout      time.Duration
	logger          Logger
	client          *http.Client
	limiter         *rate.Limiter
	visitedURLs     sync.Map
	visitedSitemaps sync.Map
	userAgent       string
}

func NewScanner(input, output, ua string, workers, rps int, logLevel string, ct, rt time.Duration) *Scanner {
	levels := map[string]int{"debug": LDEBUG, "info": LINFO, "warn": LWARN, "err": LERR}
	level, ok := levels[strings.ToLower(logLevel)]
	if !ok {
		level = LINFO
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: ct,
		}).DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &Scanner{
		inputFile:   input,
		outputFile:  output,
		workers:     workers,
		connTimeout: ct,
		reqTimeout:  rt,
		logger:      Logger{level: level},
		client: &http.Client{
			Transport: transport,
		},
		limiter:   rate.NewLimiter(rate.Limit(rps), rps),
		userAgent: ua,
	}
}

func (s *Scanner) Run() {
	jobs := make(chan string, s.workers)
	results := make(chan string, s.workers*100)
	var wg sync.WaitGroup

	go s.readInput(jobs)

	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(jobs, results)
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	s.writeOutput(results)
}

func (s *Scanner) readInput(jobs chan<- string) {
	var reader io.Reader = os.Stdin
	if s.inputFile != "-" {
		f, err := os.Open(s.inputFile)
		if err != nil {
			s.logger.Err("failed to open input: %v", err)
			panic(err)
		}
		defer f.Close()
		reader = f
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u != "" {
			jobs <- u
		}
	}
	close(jobs)
}

func (s *Scanner) worker(jobs <-chan string, results chan<- string) {
	for rawURL := range jobs {
		if _, loaded := s.visitedURLs.LoadOrStore(rawURL, true); loaded {
			s.logger.Debug("URL already checked: %s", rawURL)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), s.reqTimeout)
		if err := s.limiter.Wait(ctx); err != nil {
			cancel()
			continue
		}

		s.processHost(ctx, rawURL, results)
		cancel()
	}
}

func (s *Scanner) processHost(ctx context.Context, rawURL string, results chan<- string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		s.logger.Err("invalid URL %s: %v", rawURL, err)
		return
	}

	base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	s.logger.Info("processing host: %s", base)

	if s.fetchSitemap(ctx, base+"/sitemap.xml", results) {
		return
	}

	s.logger.Debug("no sitemap.xml at root, checking robots.txt: %s", base)
	smLinks := s.findSitemapsInRobots(ctx, base+"/robots.txt")
	if len(smLinks) == 0 {
		s.logger.Warn("no sitemap references found for %s", base)
		return
	}

	for _, link := range smLinks {
		s.fetchSitemap(ctx, link, results)
	}
}

func (s *Scanner) fetchSitemap(ctx context.Context, smURL string, results chan<- string) bool {
	if _, loaded := s.visitedSitemaps.LoadOrStore(smURL, true); loaded {
		s.logger.Debug("skipping already processed sitemap: %s", smURL)
		return false
	}

	req, err := http.NewRequestWithContext(ctx, "GET", smURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Debug("fetch error %s: %v", smURL, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger.Debug("status %d for %s", resp.StatusCode, smURL)
		return false
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		s.logger.Debug("skipping HTML response for %s (Content-Type: %s)", smURL, contentType)
		return false
	}

	lr := io.LimitReader(resp.Body, MaxBodySize)
	data, err := io.ReadAll(lr)
	if err != nil {
		s.logger.Err("read error %s: %v", smURL, err)
		return false
	}

	var si SitemapIndex
	if err := xml.Unmarshal(data, &si); err == nil && len(si.Locations) > 0 {
		s.logger.Debug("found sitemap index: %s", smURL)
		for _, loc := range si.Locations {
			s.fetchSitemap(ctx, loc, results)
		}
		return true
	}

	var sm Sitemap
	if err := xml.Unmarshal(data, &sm); err == nil && len(sm.Locations) > 0 {
		s.logger.Debug("extracted %d links from %s", len(sm.Locations), smURL)
		for _, loc := range sm.Locations {
			loc = strings.TrimSpace(loc)
			if loc != "" {
				results <- loc
			}
		}
		return true
	}

	return false
}

func (s *Scanner) findSitemapsInRobots(ctx context.Context, robotsURL string) []string {
	req, _ := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*512))
	re := regexp.MustCompile(`(?i)Sitemap:\s*(https?://\S+)`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	var found []string
	for _, m := range matches {
		found = append(found, strings.TrimSpace(m[1]))
	}
	return found
}

func (s *Scanner) writeOutput(results <-chan string) {
	var out io.Writer = os.Stdout
	if s.outputFile != "-" {
		f, err := os.Create(s.outputFile)
		if err != nil {
			s.logger.Err("output create error: %v", err)
			panic(err)
		}
		defer f.Close()
		out = f
	}

	writer := bufio.NewWriterSize(out, 128*1024)
	defer writer.Flush()

	for res := range results {
		writer.WriteString(res + "\n")
	}
}

func main() {
	i := flag.String("i", "-", "input file")
	o := flag.String("o", "-", "output file")
	ua := flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "user agent string")
	w := flag.Int("w", 50, "workers count")
	r := flag.Int("r", 150, "rps limit")
	l := flag.String("l", "info", "log level (debug, info, warn, err)")
	ct := flag.Duration("ct", 5*time.Second, "connection timeout")
	rt := flag.Duration("rt", 15*time.Second, "request timeout (context)")
	flag.Parse()

	scanner := NewScanner(*i, *o, *ua, *w, *r, *l, *ct, *rt)
	scanner.Run()
}
