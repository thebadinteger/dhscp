package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
)

var (
	colOrange = color.RGB(255, 140, 0)
	colRed    = color.New(color.FgHiRed)
	colGreen  = color.New(color.FgGreen)
)

// dahua probe packet
var hello = []byte{
	0xa0, 0x05, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00,
	0xc4, 0xa3, 0xaf, 0x48, 0x99, 0x56, 0xb6, 0xb4,
	0x70, 0x02, 0x64, 0x9a, 0xfa, 0x55, 0x24, 0x04,
	0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0xa1, 0xaa,
}

func command(commandType, commandID byte) []byte {
	pkt := make([]byte, 32)
	pkt[0] = commandType
	pkt[8] = commandID
	return pkt
}

var headerPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32)
		return &b
	},
}

// read frame from connection
func readFrame(conn net.Conn) ([]byte, error) {
	hp := headerPool.Get().(*[]byte)
	defer headerPool.Put(hp)
	header := *hp

	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	bodyLen := int(binary.LittleEndian.Uint16(header[4:6]))
	if bodyLen > 1024*1024 {
		return nil, fmt.Errorf("response body too large")
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func cleanValue(body []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(body), "\x00"))
}

func validSerial(serial string) bool {
	if len(serial) != 15 {
		return false
	}
	if serial[0] < '1' || serial[0] > '9' {
		return false
	}
	m := serial[1]
	if !((m >= 'A' && m <= 'M' && m != 'I') || (m >= 'a' && m <= 'm' && m != 'i')) {
		return false
	}
	if serial[2] != '0' && serial[2] != '1' {
		return false
	}
	for i := 3; i <= 6; i++ {
		c := serial[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	for i := 7; i <= 9; i++ {
		c := serial[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	for i := 10; i <= 14; i++ {
		c := serial[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

type deviceInfo struct {
	model  string
	serial string
}

// probe dahua device
func probeDevice(ctx context.Context, dialer *net.Dialer, address string, timeout time.Duration) (*deviceInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stop()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	pkt := make([]byte, 0, 96)
	pkt = append(pkt, hello...)
	pkt = append(pkt, command(0xa4, 0x07)...)
	pkt = append(pkt, command(0xa4, 0x0b)...)

	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}

	if _, err := readFrame(conn); err != nil {
		return nil, err
	}

	serialBody, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	serial := cleanValue(serialBody)
	if !validSerial(serial) {
		return nil, fmt.Errorf("invalid serial")
	}

	var model string
	if modelBody, err := readFrame(conn); err == nil {
		model = cleanValue(modelBody)
	}

	return &deviceInfo{model: model, serial: serial}, nil
}

type rawTarget struct {
	ip   string
	port int
}

type xmlNmapRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Addresses []xmlAddress `xml:"address"`
	Ports     xmlPorts     `xml:"ports"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type xmlPorts struct {
	PortList []xmlPort `xml:"port"`
}

type xmlPort struct {
	PortID int      `xml:"portid,attr"`
	State  xmlState `xml:"state"`
}

type xmlState struct {
	State string `xml:"state,attr"`
}

type jsonRecord struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port   int    `json:"port"`
		Status string `json:"status"`
	} `json:"ports"`
}

func parseRange(rangeStr string) []string {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil
	}
	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(startStr).To4()
	if startIP == nil {
		return nil
	}

	endIP := net.ParseIP(endStr).To4()
	if endIP == nil {
		if octet, err := strconv.Atoi(endStr); err == nil && octet >= 0 && octet <= 255 {
			endIP = make(net.IP, 4)
			copy(endIP, startIP)
			endIP[3] = byte(octet)
		} else {
			return nil
		}
	}

	startVal := binary.BigEndian.Uint32(startIP)
	endVal := binary.BigEndian.Uint32(endIP)
	if startVal > endVal {
		startVal, endVal = endVal, startVal
	}

	count := min(endVal-startVal+1, 5000000)

	res := make([]string, 0, count)
	for val := startVal; val <= startVal+count-1; val++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, val)
		res = append(res, ip.String())
	}
	return res
}

func parseCIDR(cidrStr string) []string {
	_, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil || ipnet == nil || ipnet.IP.To4() == nil {
		return nil
	}
	startVal := binary.BigEndian.Uint32(ipnet.IP.To4())
	maskVal := binary.BigEndian.Uint32(ipnet.Mask)
	endVal := startVal | (^maskVal)

	count := min(endVal-startVal+1, 5000000)

	res := make([]string, 0, count)
	for val := startVal; val <= startVal+count-1; val++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, val)
		res = append(res, ip.String())
	}
	return res
}

func parseToken(token string, items *[]rawTarget) {
	if host, portStr, err := net.SplitHostPort(token); err == nil {
		port, err := strconv.Atoi(portStr)
		if err == nil && port > 0 && port <= 65535 {
			if net.ParseIP(host) != nil {
				*items = append(*items, rawTarget{ip: host, port: port})
				return
			}
			if ips := parseCIDR(host); len(ips) > 0 {
				for _, ip := range ips {
					*items = append(*items, rawTarget{ip: ip, port: port})
				}
				return
			}
			if ips := parseRange(host); len(ips) > 0 {
				for _, ip := range ips {
					*items = append(*items, rawTarget{ip: ip, port: port})
				}
				return
			}
		}
	}

	if ips := parseCIDR(token); len(ips) > 0 {
		for _, ip := range ips {
			*items = append(*items, rawTarget{ip: ip, port: 0})
		}
		return
	}

	if strings.Contains(token, "-") {
		if ips := parseRange(token); len(ips) > 0 {
			for _, ip := range ips {
				*items = append(*items, rawTarget{ip: ip, port: 0})
			}
			return
		}
	}

	if net.ParseIP(token) != nil {
		*items = append(*items, rawTarget{ip: token, port: 0})
	}
}

// parse targets
func parseTargets(r io.Reader, defaultPorts []int) []string {
	br := bufio.NewReader(r)

	peekBytes, _ := br.Peek(512)
	trimmedPeek := strings.TrimSpace(string(peekBytes))

	if strings.HasPrefix(trimmedPeek, "<?xml") || strings.HasPrefix(trimmedPeek, "<nmaprun") {
		decoder := xml.NewDecoder(br)
		var items []rawTarget
		for {
			tok, err := decoder.Token()
			if err != nil {
				break
			}
			if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "host" {
				var h xmlHost
				if err := decoder.DecodeElement(&h, &se); err == nil {
					var ip string
					for _, a := range h.Addresses {
						if a.AddrType == "ipv4" || a.AddrType == "" {
							ip = a.Addr
							break
						}
					}
					if ip == "" && len(h.Addresses) > 0 {
						ip = h.Addresses[0].Addr
					}
					if net.ParseIP(ip) == nil {
						continue
					}
					hasPort := false
					for _, p := range h.Ports.PortList {
						if p.State.State == "open" || p.State.State == "" {
							items = append(items, rawTarget{ip: ip, port: p.PortID})
							hasPort = true
						}
					}
					if !hasPort {
						items = append(items, rawTarget{ip: ip, port: 0})
					}
				}
			}
		}
		if len(items) > 0 {
			return expandRawTargets(items, defaultPorts)
		}
	}

	if strings.HasPrefix(trimmedPeek, "[") {
		decoder := json.NewDecoder(br)
		tok, err := decoder.Token()
		if err == nil {
			if delim, ok := tok.(json.Delim); ok && delim == '[' {
				var items []rawTarget
				for decoder.More() {
					var rec jsonRecord
					if err := decoder.Decode(&rec); err == nil {
						if net.ParseIP(rec.IP) == nil {
							continue
						}
						hasPort := false
						for _, p := range rec.Ports {
							if p.Status == "open" || p.Status == "" {
								items = append(items, rawTarget{ip: rec.IP, port: p.Port})
								hasPort = true
							}
						}
						if !hasPort {
							items = append(items, rawTarget{ip: rec.IP, port: 0})
						}
					}
				}
				if len(items) > 0 {
					return expandRawTargets(items, defaultPorts)
				}
			}
		}
	}

	var items []rawTarget
	scanner := bufio.NewScanner(br)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		trimmedLine := strings.TrimSuffix(line, ",")
		if strings.HasPrefix(trimmedLine, "{") && strings.HasSuffix(trimmedLine, "}") {
			var rec jsonRecord
			if err := json.Unmarshal([]byte(trimmedLine), &rec); err == nil && rec.IP != "" {
				if net.ParseIP(rec.IP) != nil {
					hasPort := false
					for _, p := range rec.Ports {
						if p.Status == "open" || p.Status == "" {
							items = append(items, rawTarget{ip: rec.IP, port: p.Port})
							hasPort = true
						}
					}
					if !hasPort {
						items = append(items, rawTarget{ip: rec.IP, port: 0})
					}
					continue
				}
			}
		}

		if strings.Contains(line, "<address") {
			if _, rest, ok := strings.Cut(line, `addr="`); ok {
				if ip, _, ok := strings.Cut(rest, `"`); ok && net.ParseIP(ip) != nil {
					port := 0
					if _, pRest, ok := strings.Cut(line, `portid="`); ok {
						if pStr, _, ok := strings.Cut(pRest, `"`); ok {
							if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
								port = p
							}
						}
					}
					items = append(items, rawTarget{ip: ip, port: port})
					continue
				}
			}
		}

		if strings.HasPrefix(strings.ToLower(line), "open ") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				port, err := strconv.Atoi(fields[2])
				ip := fields[3]
				if err == nil && port > 0 && port <= 65535 && net.ParseIP(ip) != nil {
					items = append(items, rawTarget{ip: ip, port: port})
					continue
				}
			}
		}

		if _, rest, ok := strings.Cut(line, "Host: "); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				ip := fields[0]
				if net.ParseIP(ip) != nil {
					if _, portsStr, ok := strings.Cut(line, "Ports: "); ok {
						if before, _, ok := strings.Cut(portsStr, "\t"); ok {
							portsStr = before
						}
						pList := strings.Split(portsStr, ",")
						hasPort := false
						for _, pItem := range pList {
							pItem = strings.TrimSpace(pItem)
							slashParts := strings.Split(pItem, "/")
							if len(slashParts) >= 2 {
								state := slashParts[1]
								if state == "open" || state == "" {
									if p, err := strconv.Atoi(slashParts[0]); err == nil && p > 0 && p <= 65535 {
										items = append(items, rawTarget{ip: ip, port: p})
										hasPort = true
									}
								}
							}
						}
						if hasPort {
							continue
						}
					}
					items = append(items, rawTarget{ip: ip, port: 0})
					continue
				}
			}
		}

		for part := range strings.SplitSeq(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			parseToken(part, &items)
		}
	}
	if err := scanner.Err(); err != nil {
	}

	return expandRawTargets(items, defaultPorts)
}

func expandRawTargets(items []rawTarget, defaultPorts []int) []string {
	var res []string
	seen := make(map[string]bool)

	for _, item := range items {
		if item.port != 0 {
			target := net.JoinHostPort(item.ip, strconv.Itoa(item.port))
			if !seen[target] {
				seen[target] = true
				res = append(res, target)
			}
		} else {
			for _, p := range defaultPorts {
				target := net.JoinHostPort(item.ip, strconv.Itoa(p))
				if !seen[target] {
					seen[target] = true
					res = append(res, target)
				}
			}
		}
	}
	return res
}

func printErrorAndExit(err string) {
	colRed.Printf("[!] %s\n", err)
	os.Exit(1)
}

// print help
func printHelp() {
	nowStr := time.Now().Format("15:04:05")
	colOrange.Printf("[%s] dhscp\n", nowStr)
	fmt.Println("[-i, --input] input file or specific target(s)")
	fmt.Println("format: IP, IP:port, range, cidr, masscan")
	fmt.Println("[-o, --output] output file for results")
	fmt.Println("default > DD-MM-YYYY_HH-MM-SS")
	fmt.Println("[-t, --threads] number of threads for scanning")
	fmt.Println("default > 200")
	fmt.Println("[-p, --port] port(s) to check")
	fmt.Println("default > 37777")
	fmt.Println("[-w, --timeout] check timeout in seconds")
	fmt.Println("default > 5")
	fmt.Println("[-m, --mode] output mode: txt/csv")
	fmt.Println("default > txt")
	fmt.Println("[-?, -h, --help] get general help")
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printHelp()
		return
	}

	for _, arg := range args {
		if arg == "-?" || arg == "-h" || arg == "--help" {
			printHelp()
			return
		}
	}

	var inputArg string
	var outputArg string
	threads := 200
	portArg := "37777"
	timeoutSec := 5
	modeArg := "txt"

	// parse cli arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var key, val string
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			key = parts[0]
			val = parts[1]
		} else {
			key = arg
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				val = args[i+1]
				i++
			}
		}

		switch key {
		case "-i", "--input":
			inputArg = val
		case "-o", "--output":
			outputArg = val
		case "-t", "--threads":
			if val == "" {
				printErrorAndExit("invalid threads")
			}
			n, err := strconv.Atoi(val)
			if err != nil || n <= 0 {
				printErrorAndExit("invalid threads")
			}
			threads = n
		case "-p", "--port":
			if val == "" {
				printErrorAndExit("invalid port")
			}
			portArg = val
		case "-w", "--timeout":
			if val == "" {
				printErrorAndExit("invalid timeout")
			}
			n, err := strconv.Atoi(val)
			if err != nil || n <= 0 {
				printErrorAndExit("invalid timeout")
			}
			timeoutSec = n
		case "-m", "--mode":
			if val == "" {
				printErrorAndExit("invalid mode")
			}
			modeArg = strings.ToLower(val)
		default:
			printErrorAndExit("input invalid")
		}
	}

	if inputArg == "" {
		printErrorAndExit("input invalid")
	}

	if modeArg != "txt" && modeArg != "csv" {
		printErrorAndExit("invalid mode")
	}

	var defaultPorts []int
	for pStr := range strings.SplitSeq(portArg, ",") {
		pStr = strings.TrimSpace(pStr)
		p, err := strconv.Atoi(pStr)
		if err != nil || p < 1 || p > 65535 {
			printErrorAndExit("invalid port")
		}
		defaultPorts = append(defaultPorts, p)
	}

	var r io.Reader
	fileInfo, err := os.Stat(inputArg)
	if err == nil && !fileInfo.IsDir() {
		f, err := os.Open(inputArg)
		if err != nil {
			printErrorAndExit(fmt.Sprintf("error: %s", err))
		}
		defer f.Close()
		r = f
	} else {
		if strings.Contains(inputArg, "\\") || strings.HasSuffix(inputArg, ".txt") || strings.HasSuffix(inputArg, ".json") || strings.HasSuffix(inputArg, ".xml") || strings.HasSuffix(inputArg, ".csv") || strings.HasSuffix(inputArg, ".log") {
			printErrorAndExit("input file not found")
		}
		if strings.Contains(inputArg, "/") && !strings.ContainsAny(inputArg, "0123456789") {
			printErrorAndExit("input file not found")
		}
		r = strings.NewReader(inputArg)
	}

	targets := parseTargets(r, defaultPorts)
	if len(targets) == 0 {
		if err != nil && (strings.Contains(inputArg, ".") || strings.Contains(inputArg, "/") || strings.Contains(inputArg, "\\")) {
			printErrorAndExit("input file not found")
		}
		printErrorAndExit("input invalid")
	}

	if outputArg == "" {
		outputArg = time.Now().Format("02-01-2006_15-04-05") + "." + modeArg
	} else if filepath.Ext(outputArg) == "" {
		outputArg = outputArg + "." + modeArg
	}

	outDir := filepath.Dir(outputArg)
	if outDir != "" && outDir != "." {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			printErrorAndExit("cannot create output")
		}
	}

	seenPrefixes := make(map[string]bool)
	var fileExists bool
	if existingF, err := os.Open(outputArg); err == nil {
		if fi, err := existingF.Stat(); err == nil && fi.Size() > 0 {
			fileExists = true
		}
		scanner := bufio.NewScanner(existingF)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if modeArg == "csv" {
				if strings.EqualFold(line, "model,prefix") || strings.EqualFold(line, "ip,model,prefix") {
					continue
				}
				parts := strings.Split(line, ",")
				if len(parts) == 2 {
					seenPrefixes[strings.TrimSpace(parts[1])] = true
				} else if len(parts) >= 3 {
					seenPrefixes[strings.TrimSpace(parts[2])] = true
				}
			} else {
				seenPrefixes[line] = true
			}
		}
		if err := scanner.Err(); err != nil {
		}
		existingF.Close()
	}

	outF, err := os.OpenFile(outputArg, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		printErrorAndExit("cannot create output")
	}
	defer outF.Close()

	var fileMu sync.Mutex
	if modeArg == "csv" && !fileExists {
		outF.WriteString("model,prefix\n")
	}

	total := len(targets)
	var checked atomic.Int64

	nowStr := time.Now().Format("15:04:05")
	colOrange.Printf("[%s] dhscp\n", nowStr)
	fmt.Printf("input > %s\n", inputArg)
	fmt.Printf("output > %s\n", outputArg)
	fmt.Printf("threads > %d\n", threads)
	fmt.Printf("port > %s\n", portArg)
	fmt.Printf("timeout > %d\n", timeoutSec)
	fmt.Printf("mode > %s\n", modeArg)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	var printMu sync.Mutex
	var latestMu sync.Mutex
	var latest string

	var interrupted atomic.Bool
	cancelChan := make(chan struct{})
	var cancelOnce sync.Once

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigChan {
			if interrupted.CompareAndSwap(false, true) {
				cancelOnce.Do(func() {
					rootCancel()
					close(cancelChan)
				})
				nowStr := time.Now().Format("15:04:05")
				printMu.Lock()
				fmt.Print("\r\n")
				colRed.Printf("[%s] interrupted\n", nowStr)
				printMu.Unlock()
			} else {
				os.Exit(1)
			}
		}
	}()

	doneChan := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		var lastLen int
		for {
			select {
			case <-doneChan:
				return
			case <-cancelChan:
				return
			case <-ticker.C:
				if interrupted.Load() {
					return
				}
				if color.NoColor {
					continue
				}
				c := checked.Load()
				latestMu.Lock()
				lat := latest
				latestMu.Unlock()
				line := fmt.Sprintf("[%d/%d] %s", c, total, lat)
				if lat == "" {
					line = fmt.Sprintf("[%d/%d]", c, total)
				}
				pad := 0
				if len(line) < lastLen {
					pad = lastLen - len(line)
				}
				lastLen = len(line)
				printMu.Lock()
				if !interrupted.Load() {
					fmt.Fprintf(color.Output, "\r\033[2K%s%s", line, strings.Repeat(" ", pad))
				}
				printMu.Unlock()
			}
		}
	}()

	scanTimeout := time.Duration(timeoutSec) * time.Second
	dialer := &net.Dialer{}
	workChan := make(chan string, threads*16)
	var wg sync.WaitGroup

	// scan worker
	for i := 0; i < threads; i++ {
		wg.Go(func() {
			for {
				select {
				case <-cancelChan:
					return
				case target, ok := <-workChan:
					if !ok {
						return
					}
					if interrupted.Load() {
						return
					}

					info, err := probeDevice(rootCtx, dialer, target, scanTimeout)
					if interrupted.Load() {
						return
					}
					checked.Add(1)
					if err != nil {
						continue
					}

					prefix := info.serial
					if len(prefix) > 10 {
						prefix = prefix[:10]
					}
					host, port, _ := net.SplitHostPort(target)
					displayIP := host
					if port != "37777" {
						displayIP = target
					}

					model := info.model
					if model == "" {
						model = "n/a"
					}

					resStr := fmt.Sprintf("%s > %s | %s", displayIP, model, info.serial)
					latestMu.Lock()
					latest = resStr
					latestMu.Unlock()

					fileMu.Lock()
					if !seenPrefixes[prefix] {
						seenPrefixes[prefix] = true
						if modeArg == "csv" {
							fmt.Fprintf(outF, "%s,%s\n", model, prefix)
						} else {
							fmt.Fprintf(outF, "%s\n", prefix)
						}
					}
					fileMu.Unlock()
				}
			}
		})
	}

feed:
	for _, target := range targets {
		select {
		case <-cancelChan:
			break feed
		case workChan <- target:
		}
	}
	close(workChan)

	wg.Wait()
	close(doneChan)

	if !interrupted.Load() {
		c := checked.Load()
		latestMu.Lock()
		lat := latest
		latestMu.Unlock()
		line := fmt.Sprintf("[%d/%d] %s", c, total, lat)
		if lat == "" {
			line = fmt.Sprintf("[%d/%d]", c, total)
		}
		printMu.Lock()
		if !color.NoColor {
			fmt.Fprintf(color.Output, "\r\033[2K%s\n", line)
		} else {
			fmt.Println(line)
		}
		nowStr := time.Now().Format("15:04:05")
		colGreen.Printf("[%s] done!\n", nowStr)
		printMu.Unlock()
	}
}
