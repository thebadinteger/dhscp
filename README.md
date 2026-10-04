<h1 align="center">dhscp</h1>  
<h3 align="center">Dahua cameras serial number prefix scraper</h3>  
<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26%2B-00647d?style=flat&logo=go&logoColor=ffffff" alt="Go"/>
</p>  

## Installation:  
**Build from source:**  
```shell
git clone https://github.com/thebadinteger/dhscp.git
cd dhscp
go build
```  
Or download the latest binary from the **[Releases page](https://github.com/thebadinteger/dhscp/releases/latest)**.  

## Usage:  
```shell
./dhscp scan -i [input] -o [output] -t [threads] -p [port] -w [timeout] -m [mode]
./dhscp parse -i [input] -o [output] -g [model,part*] -m [mode]
```  
```
[scan, parse] session mode
default > scan
[-i, --input] input file or specific target(s)
format: IP, IP:port, range, cidr, masscan
[-o, --output] output file for results
default > DD-MM-YYYY_HH-MM-SS
[-t, --threads] number of threads for scanning
default > 200
[-p, --port] port(s) to check
default > 37777
[-g, --get] get model(s) from csv output
default > *
[-w, --timeout] check timeout in seconds
default > 5
[-m, --mode] output mode: txt/csv
default > txt
[-?, -h, --help] get general help
```  

**Input format:**  
ip, ip:port, range, cidr, masscan output (-oG, -oL, -oX, -oJ)
```
0.0.0.0
1.1.1.1:37777
2.2.2.2-2.2.2.255
3.3.3.3/24
```  
**Output format:**  
txt:
```
prefix
prefix
prefix
```  
csv:  
```
model,prefix
```
