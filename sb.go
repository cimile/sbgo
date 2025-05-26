// sb.go
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	singBoxDir         = "/etc/s-box"
	singBoxBinary      = "/etc/s-box/sing-box"
	singBoxConfig      = "/etc/s-box/sb.json"
	selfSignedCert     = "/etc/s-box/self_signed_cert.pem"
	selfSignedKey      = "/etc/s-box/self_signed_key.pem"
	systemdServiceFile = "/etc/systemd/system/sing-box.service"
	defaultSNI         = "www.bing.com"
	realitySNI         = "www.bing.com"
	defaultUserAgent   = "sb-manager-go/3.9" // Version bump
	installConfigFile  = "/etc/s-box/install_data.json"
	acmeBaseDir        = "/etc/s-box/acme"
	cliCommandName     = "sb"
)

const (
	ColorReset  = "\033[0m"; ColorRed    = "\033[31m"; ColorGreen  = "\033[32m"; ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"; ColorPurple = "\033[35m"; ColorCyan   = "\033[36m"; ColorWhite  = "\033[37m"
)

// --- Struct Definitions ---
type SingBoxLogConfig struct { Disabled  bool   `json:"disabled"`; Level     string `json:"level"`; Timestamp bool   `json:"timestamp"`}
type SingBoxUser struct { UUID string `json:"uuid,omitempty"`; Flow string `json:"flow,omitempty"`; AlterID  int `json:"alterId,omitempty"`; Password string `json:"password,omitempty"`}
type SingBoxRealityHandshake struct { Server string `json:"server"`; ServerPort uint16 `json:"server_port"`}
type SingBoxRealityConfig struct { Enabled bool `json:"enabled"`; Handshake SingBoxRealityHandshake `json:"handshake"`; PrivateKey string `json:"private_key"`; ShortID []string `json:"short_id"`}
type SingBoxTLSConfig struct { Enabled bool `json:"enabled"`; ServerName string `json:"server_name,omitempty"`; CertificatePath string `json:"certificate_path,omitempty"`; KeyPath string `json:"key_path,omitempty"`; Reality *SingBoxRealityConfig `json:"reality,omitempty"`; ALPN []string `json:"alpn,omitempty"`}
type SingBoxTransportConfig struct { Type string `json:"type"`; Path string `json:"path,omitempty"`; MaxEarlyData int `json:"max_early_data,omitempty"`; EarlyDataHeaderName string `json:"early_data_header_name,omitempty"`}
type SingBoxInbound struct { Type string `json:"type"`; Tag string `json:"tag"`; Listen string `json:"listen"`; ListenPort uint16 `json:"listen_port"`; Sniff bool `json:"sniff"`; SniffOverrideDestination bool `json:"sniff_override_destination"`; Users []SingBoxUser `json:"users"`; TLS *SingBoxTLSConfig `json:"tls,omitempty"`; Transport *SingBoxTransportConfig `json:"transport,omitempty"`; CongestionControl string `json:"congestion_control,omitempty"`; IgnoreClientBandwidth bool `json:"ignore_client_bandwidth,omitempty"`}
type SingBoxOutbound struct { Type string `json:"type"`; Tag string `json:"tag"`; DomainStrategy string `json:"domain_strategy,omitempty"`}
type SingBoxRouteRule struct { Protocol []string `json:"protocol,omitempty"`; Network string `json:"network,omitempty"`; Outbound string `json:"outbound"`}
type SingBoxRouteConfig struct { Rules []SingBoxRouteRule `json:"rules"` }
type SingBoxServerConfig struct { Log SingBoxLogConfig `json:"log"`; Inbounds  []SingBoxInbound `json:"inbounds"`; Outbounds []SingBoxOutbound `json:"outbounds"`; Route SingBoxRouteConfig `json:"route"`}
type InstallData struct {
	ServerIP          string           `json:"server_ip"`
	Hostname          string           `json:"hostname"`
	Ports             map[string]uint16 `json:"ports"`
	MainUUID          string           `json:"main_uuid"`
	RealityPrivateKey string           `json:"reality_private_key"`
	RealityPublicKey  string           `json:"reality_public_key"`
	RealityShortID    string           `json:"reality_short_id"`
	Domain            string           `json:"domain,omitempty"`
	VmessPath         string           `json:"vmess_path"`
	UseAcmeCert       bool             `json:"use_acme_cert"`
	AcmeEmail         string           `json:"acme_email,omitempty"` // Added AcmeEmail field
}
var currentInstallData InstallData

func main() { /* ... Identical to previous versions ... */
	loadInstallData();for{printMainMenu();choice:=getUserInput(ColorYellow+"Enter your choice: "+ColorReset);clearScreen();switch choice{case"1":installInteractive();case"2":uninstall();case"3":manageNodes();case"4":manageCertificates();case"5":generateAndShowSubscription();case"6":restartSingBoxServiceInteractive();case"7":stopSingBoxServiceInteractive();case"8":startSingBoxServiceInteractive();case"9":viewSingBoxLogs();case"10":checkSingBoxStatusInteractive();case"0":fmt.Println(ColorGreen+"Exiting."+ColorReset);os.Exit(0);default:fmt.Printf("%sInvalid choice. Please try again.%s\n",ColorRed,ColorReset)};if choice!="0"&&choice!="9"&&choice!="10"{fmt.Printf("\n%sPress Enter to continue...%s",ColorYellow,ColorReset);bufio.NewReader(os.Stdin).ReadBytes('\n')}}}

func clearScreen(){ /* ... Identical to previous versions ... */ cmd:=exec.Command("clear");if runtime.GOOS=="windows"{cmd=exec.Command("cmd","/c","cls")};cmd.Stdout=os.Stdout;cmd.Run()}
func getSingBoxStatus()(string,bool){ /* ... Use the corrected version from my reply before your "func buildSingBoxServerConfig()... too many errors" one ... */
	_,statErr:=os.Stat(systemdServiceFile);if os.IsNotExist(statErr){return"Not Installed",false};if statErr!=nil{return fmt.Sprintf("Error stating service file: %v",statErr),false}
	stCmd:=exec.Command("systemctl","is-active","sing-box");stOut,e:=stCmd.Output();stStr:=strings.TrimSpace(string(stOut))
	if e!=nil{flCmd:=exec.Command("systemctl","is-failed","sing-box");flOut,_:=flCmd.Output();flStr:=strings.TrimSpace(string(flOut));if flStr=="failed"{return"Failed",false};return"Inactive/Stopped",false}
	if stStr=="active"{return"Active (Running)",true};return strings.Title(stStr),false
}
func printMainMenu(){ /* ... Identical to previous versions ... */ clearScreen();statusText,isRun:=getSingBoxStatus();stColor:=ColorYellow;if isRun{stColor=ColorGreen}else if statusText=="Failed"||statusText=="Not Installed"{stColor=ColorRed};managerTitle:=fmt.Sprintf("%sSing-box Manager (%s)%s",ColorCyan,cliCommandName,ColorReset);statusLine:=fmt.Sprintf("%sStatus: %s%s",stColor,statusText,ColorReset);fmt.Printf("\n--- %s --- %s ---\n",managerTitle,statusLine);fmt.Printf("%s1. Install/Reinstall Sing-box%s\n",ColorGreen,ColorReset);fmt.Printf("%s2. Uninstall Sing-box%s\n",ColorRed,ColorReset);fmt.Printf("%s3. Show Nodes%s\n",ColorGreen,ColorReset);fmt.Printf("%s4. Manage Certificates (Switch Self-signed/ACME)%s\n",ColorGreen,ColorReset);fmt.Printf("%s5. Generate & Show Subscription Link%s\n",ColorGreen,ColorReset);fmt.Printf("%s--- Service Management ---%s\n",ColorBlue,ColorReset);fmt.Printf("%s6. Restart Sing-box%s\n",ColorYellow,ColorReset);fmt.Printf("%s7. Stop Sing-box%s\n",ColorYellow,ColorReset);fmt.Printf("%s8. Start Sing-box%s\n",ColorYellow,ColorReset);fmt.Printf("%s9. View Sing-box Logs%s\n",ColorYellow,ColorReset);fmt.Printf("%s10. Check Sing-box Status%s\n",ColorCyan,ColorReset);fmt.Printf("%s0. Exit%s\n",ColorYellow,ColorReset);fmt.Println(strings.Repeat("-",50))}
func checkSingBoxStatusInteractive(){ /* ... Identical to previous versions ... */ fmt.Printf("%sChecking Sing-box service status...%s\n",ColorYellow,ColorReset);statusText,isRun:=getSingBoxStatus();stColor:=ColorYellow;if isRun{stColor=ColorGreen}else if statusText=="Failed"||statusText=="Not Installed"{stColor=ColorRed};fmt.Printf("Sing-box Service Status: %s%s%s\n",stColor,statusText,ColorReset);if!isRun&&statusText!="Not Installed"{fmt.Printf("%sUse option '9' for detailed logs if service failed.%s\n",ColorYellow,ColorReset)}}
func getUserInput(p string)string{ /* ... Identical to previous versions ... */ fmt.Print(p);r:=bufio.NewReader(os.Stdin);in,_:=r.ReadString('\n');return strings.TrimSpace(in)}
func runCommand(n string,a ...string)(string,error){ /* ... Identical to previous versions ... */ c:=exec.Command(n,a...);var o,s bytes.Buffer;c.Stdout=&o;c.Stderr=&s;e:=c.Run();if e!=nil{return"",fmt.Errorf("command %s %v failed: %w\nStdout: %s\nStderr: %s",n,a,e,strings.ToValidUTF8(o.String(),""),strings.ToValidUTF8(s.String(),""))};return o.String(),nil}
func checkRoot(){ /* ... Identical to previous versions ... */ if os.Geteuid()!=0{log.Fatalf("%sRoot privileges required.%s",ColorRed,ColorReset)}}
func checkOS(){ /* ... Identical to previous versions ... */ if _,e:=os.Stat("/etc/debian_version");e!=nil{b,fe:=os.ReadFile("/etc/os-release");if fe!=nil{fmt.Printf("%sWarning: OS check failed: %v%s\n",ColorYellow,fe,ColorReset);if strings.ToLower(getUserInput(ColorYellow+"Is this Debian-based? (y/N): "+ColorReset))!="y"{log.Fatalf("%sOS not confirmed Debian-based.%s",ColorRed,ColorReset)};return};s:=string(b);if !strings.Contains(s,"ID_LIKE=debian")&&!strings.Contains(s,"ID=debian")&&!strings.Contains(s,"ID=ubuntu"){log.Fatalf("%sUnsupported OS.%s",ColorRed,ColorReset)}};fmt.Printf("%sOS check OK.%s\n",ColorGreen,ColorReset)}
func installDependencies(){ /* ... Identical to previous versions ... */ fmt.Printf("%sUpdating apt...%s\n",ColorYellow,ColorReset);if _,e:=runCommand("apt-get","update","-y");e!=nil{log.Fatalf("%sApt fail: %v%s",ColorRed,e,ColorReset)};d:=[]string{"curl","wget","jq","qrencode","openssl","iproute2","iptables","ca-certificates","certbot"};fmt.Printf("%sDeps: %v%s\n",ColorYellow,d,ColorReset);installArgs:=[]string{"install","-y"};installArgs=append(installArgs,d...);if _,e:=runCommand("apt-get",installArgs...);e!=nil{if strings.Contains(e.Error(),"certbot"){fmt.Printf("%sWARN: apt install certbot failed. Try snap.%s\n",ColorYellow,ColorReset);fmt.Printf("%sCmd: sudo apt install snapd && sudo snap install --classic certbot && sudo ln -s /snap/bin/certbot /usr/bin/certbot%s\n",ColorCyan,ColorReset)}else{log.Fatalf("%sDeps fail: %v%s",ColorRed,e,ColorReset)}};fmt.Printf("%sDeps attempted.%s\n",ColorGreen,ColorReset);if _,e:=exec.LookPath("certbot");e!=nil{fmt.Printf("%sWARN: certbot still not found. Manual install needed for ACME.%s\n",ColorYellow,ColorReset)}else{fmt.Printf("%sCertbot OK.%s\n",ColorGreen,ColorReset)}}
func getCPUArch()string{ /* ... Identical to previous versions ... */ a:=runtime.GOARCH;if a=="amd64"||a=="arm64"{return a};log.Fatalf("%sArch %s unsupported.%s",ColorRed,a,ColorReset);return ""}
func downloadAndInstallSingBox(){ /* ... Identical to previous versions ... */ fmt.Printf("%sDL/Install Sing-box...%s\n",ColorYellow,ColorReset);arch:=getCPUArch();c:=&http.Client{Timeout:30*time.Second};req,_:=http.NewRequest("GET","https://api.github.com/repos/SagerNet/sing-box/releases/latest",nil);req.Header.Set("User-Agent",defaultUserAgent);req.Header.Set("Accept","application/vnd.github.v3+json");res,e:=c.Do(req);if e!=nil{log.Fatalf("Fetch release failed: %v",e)};defer res.Body.Close();if res.StatusCode!=http.StatusOK{b,_:=io.ReadAll(res.Body);log.Fatalf("Fetch release status %d: %s",res.StatusCode,string(b))};var ri struct{TagName string `json:"tag_name"`;Assets[]struct{Name string `json:"name"`;URL string `json:"browser_download_url"`}`json:"assets"`};if json.NewDecoder(res.Body).Decode(&ri)!=nil{log.Fatalf("Parse release JSON failed")};var dlURL string;sfx:=fmt.Sprintf("linux-%s.tar.gz",arch);for _,a:=range ri.Assets{if strings.HasPrefix(a.Name,"sing-box-")&&strings.HasSuffix(a.Name,sfx){dlURL=a.URL;fmt.Printf("%sFound: %s%s\n",ColorGreen,a.Name,ColorReset);break}};if dlURL==""{log.Fatalf("No URL for %s in %s",arch,ri.TagName)};fmt.Printf("%sDL from %s%s\n",ColorYellow,dlURL,ColorReset);os.MkdirAll(singBoxDir,0755);dlP:=filepath.Join(os.TempDir(),filepath.Base(dlURL));outF,e:=os.Create(dlP);if e!=nil{log.Fatalf("Create DL file fail: %v",e)};dlR,e:=c.Get(dlURL);if e!=nil{outF.Close();os.Remove(dlP);log.Fatalf("DL fail: %v",e)};defer dlR.Body.Close();if dlR.StatusCode!=http.StatusOK{outF.Close();os.Remove(dlP);log.Fatalf("DL status %d",dlR.StatusCode)};_,e=io.Copy(outF,dlR.Body);outF.Close();if e!=nil{os.Remove(dlP);log.Fatalf("Save DL fail: %v",e)};fmt.Printf("%sExtract...%s\n",ColorYellow,ColorReset);uDir:=filepath.Join(os.TempDir(),"sb-extract");os.RemoveAll(uDir);os.MkdirAll(uDir,0755);if _,e:=runCommand("tar","-xzf",dlP,"-C",uDir);e!=nil{log.Fatalf("Extract fail: %v",e)};var binP string;filepath.Walk(uDir,func(p string,i os.FileInfo,we error)error{if we!=nil{return we};if !i.IsDir()&&i.Name()=="sing-box"{binP=p;return filepath.SkipDir};return nil});if binP==""{log.Fatalf("Binary not found")};inF,_:=os.Open(binP);defer inF.Close();dstF,_:=os.Create(singBoxBinary);defer dstF.Close();io.Copy(dstF,inF);os.Chmod(singBoxBinary,0755);if e:=os.Remove(binP);e!=nil{fmt.Printf("%sWARN:Could not remove temp binary: %v%s\n",ColorYellow,e,ColorReset)};os.Remove(dlP);os.RemoveAll(uDir);v,_:=runCommand(singBoxBinary,"version");fmt.Printf("%sInstalled: %s%s\n",ColorGreen,strings.TrimSpace(v),ColorReset)}
func generateSelfSignedCert(){ /* ... Identical to previous versions ... */ fmt.Printf("%sGen self-signed...%s\n",ColorYellow,ColorReset);priv,_:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);now:=time.Now();tpl:=x509.Certificate{SerialNumber:big.NewInt(now.Unix()),Subject:pkix.Name{CommonName:defaultSNI},NotBefore:now,NotAfter:now.AddDate(10,0,0),KeyUsage:x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},DNSNames:[]string{defaultSNI},BasicConstraintsValid:true,IsCA:true};der,_:=x509.CreateCertificate(rand.Reader,&tpl,&tpl,&priv.PublicKey,priv);co,_:=os.Create(selfSignedCert);defer co.Close();pem.Encode(co,&pem.Block{Type:"CERTIFICATE",Bytes:der});ko,_:=os.Create(selfSignedKey);defer ko.Close();pb,_:=x509.MarshalECPrivateKey(priv);pem.Encode(ko,&pem.Block{Type:"EC PRIVATE KEY",Bytes:pb});fmt.Printf("%sSelf-signed OK.%s\n",ColorGreen,ColorReset)}
func getPort(p string,sug uint16)uint16{ /* ... Identical to previous versions ... */ r:=bufio.NewReader(os.Stdin);pr,dh:=strings.ToValidUTF8(p,""),"random";if sug>0{dh=fmt.Sprintf("%d or random",sug)};for{fmt.Printf("%s (default:%s,10k-65k): ",pr,dh);ln,_:=r.ReadString('\n');ln=strings.TrimSpace(ln);if ln==""{if sug>0{fmt.Printf("Using previous/default: %d\n",sug);return sug};return generateRandomPort(uint16(20000+time.Now().Nanosecond()%10000))};pt,e:=strconv.Atoi(ln);if e==nil&&pt>=10000&&pt<=65535{return uint16(pt)};fmt.Printf("%sInvalid port. Try again.%s\n",ColorRed,ColorReset)}}
func generateRandomPort(fallbk uint16)uint16{ /* ... Identical to previous versions ... */ for i:=0;i<20;i++{n,e:=rand.Int(rand.Reader,big.NewInt(55536));if e!=nil{continue};p:=uint16(n.Int64()+10000);l,_:=net.Listen("tcp",fmt.Sprintf(":%d",p));if l!=nil{l.Close();lp,_:=net.ListenPacket("udp",fmt.Sprintf(":%d",p));if lp!=nil{lp.Close();fmt.Printf("%sGenerated random port: %d%s\n",ColorGreen,p,ColorReset);return p}}};fmt.Printf("%sWARN: Rand port fail, using fallback %d%s\n",ColorYellow,fallbk,ColorReset);return fallbk}
func generateSingBoxUUID()string{ /* ... Identical to previous versions ... */ return uuid.NewString()}
func generateRealityKeyPair()(privK,pubK,sID string,err error){ /* ... Identical to previous versions ... */ if _,e:=os.Stat(singBoxBinary);os.IsNotExist(e){return"","","",fmt.Errorf("sing-box not found")};out,e:=runCommand(singBoxBinary,"generate","reality-keypair");if e!=nil{return"","","",e};s:=bufio.NewScanner(strings.NewReader(out));for s.Scan(){ln:=s.Text();ps:=strings.SplitN(ln,":",2);if len(ps)==2{k,v:=strings.TrimSpace(ps[0]),strings.TrimSpace(ps[1]);if k=="PrivateKey"{privK=v};if k=="PublicKey"{pubK=v}}};if s.Err()!=nil{return"","","",s.Err()};if privK==""||pubK==""{return"","","",fmt.Errorf("parse keys fail:%s",out)};sout,e:=runCommand(singBoxBinary,"generate","rand","--hex","4");if e!=nil{return"","","",e};return privK,pubK,strings.TrimSpace(sout),nil}
func saveInstallData(){ /* ... Identical to previous versions ... */ d,e:=json.MarshalIndent(currentInstallData,"","  ");if e!=nil{fmt.Printf("%sWARN:Marshal install_data.json: %v%s\n",ColorYellow,e,ColorReset);return};if e=os.WriteFile(installConfigFile,d,0600);e!=nil{fmt.Printf("%sWARN:Save install_data.json: %v%s\n",ColorYellow,e,ColorReset)}}
func loadInstallData(){ /* ... Identical to previous versions (with pointer fix and AcmeEmail init) ... */ if e:=os.MkdirAll(singBoxDir,0755);e!=nil&&!os.IsExist(e){fmt.Printf("%sWARN:Mkdir %s: %v%s\n",ColorYellow,singBoxDir,e,ColorReset)};if _,e:=os.Stat(installConfigFile);e!=nil{currentInstallData.Ports=make(map[string]uint16);currentInstallData.ServerIP=getPublicIP();currentInstallData.Hostname,_=os.Hostname();if currentInstallData.Hostname==""{currentInstallData.Hostname="sb-server"};currentInstallData.UseAcmeCert=false;currentInstallData.Domain="";currentInstallData.AcmeEmail="";if !os.IsNotExist(e){fmt.Printf("%sWARN:Stat %s: %v. Defaults.%s\n",ColorYellow,installConfigFile,e,ColorReset)}else{fmt.Printf("%sNo install config. Defaults.%s\n",ColorYellow,ColorReset)};return};d,e:=os.ReadFile(installConfigFile);if e!=nil{fmt.Printf("%sWARN:Read %s:%v. Defaults.%s\n",ColorYellow,installConfigFile,e,ColorReset);currentInstallData.Ports=make(map[string]uint16);currentInstallData.ServerIP=getPublicIP();currentInstallData.Hostname,_=os.Hostname();if currentInstallData.Hostname==""{currentInstallData.Hostname="sb-server"};currentInstallData.UseAcmeCert=false;currentInstallData.Domain="";currentInstallData.AcmeEmail="";return};if errU:=json.Unmarshal(d,&currentInstallData);errU!=nil{fmt.Printf("%sWARN:Unmarshal %s failed: %v. Content: <%s>. Defaults used.%s\n",ColorYellow,installConfigFile,errU,string(d),ColorReset);currentInstallData.Ports=make(map[string]uint16);currentInstallData.ServerIP=getPublicIP();currentInstallData.Hostname,_=os.Hostname();if currentInstallData.Hostname==""{currentInstallData.Hostname="sb-server"};currentInstallData.MainUUID="";currentInstallData.RealityPrivateKey="";currentInstallData.RealityPublicKey="";currentInstallData.RealityShortID="";currentInstallData.VmessPath="";currentInstallData.UseAcmeCert=false;currentInstallData.Domain="";currentInstallData.AcmeEmail="";return};if currentInstallData.Ports==nil{currentInstallData.Ports=make(map[string]uint16)};if currentInstallData.ServerIP==""{currentInstallData.ServerIP=getPublicIP()};if currentInstallData.Hostname==""{currentInstallData.Hostname,_=os.Hostname();if currentInstallData.Hostname==""{currentInstallData.Hostname="sb-server"}}; // Initialize AcmeEmail if not set
    if currentInstallData.AcmeEmail == "" { currentInstallData.AcmeEmail = "" }
	fmt.Printf("%sInstall data loaded from %s%s\n",ColorGreen,installConfigFile,ColorReset)}

// Corrected buildSingBoxServerConfig
func buildSingBoxServerConfig() SingBoxServerConfig {
	cfg := currentInstallData
	certP, keyP := selfSignedCert, selfSignedKey
	vmSNI, h2SNI, tSNI := defaultSNI, defaultSNI, defaultSNI
	isAcmeEffective := false

	if cfg.UseAcmeCert && cfg.Domain != "" {
		domainAcmeDir := filepath.Join(acmeBaseDir, cfg.Domain)
		acmeCertPath := filepath.Join(domainAcmeDir, "fullchain.pem")
		acmeKeyPath := filepath.Join(domainAcmeDir, "privkey.pem")

		// Important: Set these SNI/addresses to the domain ONLY if ACME certs are effective
		// Otherwise, they should remain defaultSNI/IP as initially set
		if _, certErr := os.Stat(acmeCertPath); certErr == nil {
			if _, keyErr := os.Stat(acmeKeyPath); keyErr == nil {
				isAcmeEffective = true
			}
		}
		
		if isAcmeEffective {
			certP = acmeCertPath
			keyP = acmeKeyPath
			vmSNI, h2SNI, tSNI = cfg.Domain, cfg.Domain, cfg.Domain
			fmt.Printf("%sServer config: Using ACME certificate for domain: %s (files found).%s\n", ColorGreen, cfg.Domain, ColorReset)
		} else {
			// ACME was intended, but files not found. Fallback to self-signed behavior for config, but warn.
			// The paths will remain self-signed, and SNIs will remain default.
			fmt.Printf("%sCRITICAL WARN: Server config set to use ACME for '%s', but certificate files NOT FOUND at expected paths.%s\n", ColorRed, cfg.Domain, ColorReset)
			fmt.Printf("%s  Expected cert: %s\n", ColorRed, acmeCertPath, ColorReset)
			fmt.Printf("%s  Expected key:  %s\n", ColorRed, acmeKeyPath, ColorReset)
			fmt.Printf("%s  Sing-box will LIKELY FAIL TO START or serve TLS correctly until these files are placed! Default SNI will be used.%s\n", ColorRed, ColorReset)
			// Ensure certP and keyP revert to self-signed if ACME files are missing,
			// even if UseAcmeCert was true in currentInstallData.
			certP = selfSignedCert
			keyP = selfSignedKey
			// vmSNI, h2SNI, tSNI are already defaultSNI, no change needed.
		}
	} else {
		_, selfCertStatErr := os.Stat(selfSignedCert)
		_, selfKeyStatErr := os.Stat(selfSignedKey)
		if os.IsNotExist(selfCertStatErr) || os.IsNotExist(selfKeyStatErr) {
			fmt.Printf("%sSelf-signed cert/key not found (default mode), generating now...%s\n", ColorYellow, ColorReset)
			generateSelfSignedCert()
		}
		fmt.Printf("%sServer config: Using self-signed certificate (SNI for non-VLESS: %s)%s\n", ColorGreen, defaultSNI, ColorReset)
		// certP and keyP are already selfSignedCert/Key, no change needed.
	}

	if cfg.VmessPath == "" { cfg.VmessPath = fmt.Sprintf("/%s-vm", cfg.MainUUID) }

	return SingBoxServerConfig{
		Log: SingBoxLogConfig{Level: "info", Timestamp: true},
		Inbounds: []SingBoxInbound{
            { Type: "vless", Tag: "vless-in", Listen: "::", ListenPort: cfg.Ports["vless"], Sniff: false, SniffOverrideDestination: false, Users: []SingBoxUser{{UUID: cfg.MainUUID, Flow: "xtls-rprx-vision"}}, TLS: &SingBoxTLSConfig{Enabled: true, ServerName: realitySNI, Reality: &SingBoxRealityConfig{Enabled: true, Handshake: SingBoxRealityHandshake{Server: realitySNI, ServerPort: 443}, PrivateKey: cfg.RealityPrivateKey, ShortID: []string{cfg.RealityShortID}}}},
			{ Type: "vmess", Tag: "vmess-in", Listen: "::", ListenPort: cfg.Ports["vmess"], Sniff: false, SniffOverrideDestination: false, Users: []SingBoxUser{{UUID: cfg.MainUUID, AlterID: 0}}, Transport: &SingBoxTransportConfig{Type: "ws", Path: cfg.VmessPath, MaxEarlyData: 2048, EarlyDataHeaderName: "Sec-WebSocket-Protocol"}, TLS: &SingBoxTLSConfig{Enabled: true, ServerName: vmSNI, CertificatePath: certP, KeyPath: keyP}}, // MODIFIED: Sniff and SniffOverrideDestination set to false
			{ Type: "hysteria2", Tag: "hy2-in", Listen: "::", ListenPort: cfg.Ports["hysteria2"], Sniff: false, SniffOverrideDestination: false, Users: []SingBoxUser{{Password: cfg.MainUUID}}, IgnoreClientBandwidth: false, TLS: &SingBoxTLSConfig{Enabled: true, ALPN: []string{"h3"}, CertificatePath: certP, KeyPath: keyP, ServerName: h2SNI}}, // MODIFIED: Sniff and SniffOverrideDestination set to false
			{ Type: "tuic", Tag: "tuic5-in", Listen: "::", ListenPort: cfg.Ports["tuic"], Sniff: false, SniffOverrideDestination: false, Users: []SingBoxUser{{UUID: cfg.MainUUID, Password: cfg.MainUUID}}, CongestionControl: "bbr", TLS: &SingBoxTLSConfig{Enabled: true, ALPN: []string{"h3"}, CertificatePath: certP, KeyPath: keyP, ServerName: tSNI}}}, // MODIFIED: Sniff and SniffOverrideDestination set to false
		Outbounds: []SingBoxOutbound{{Type: "direct", Tag: "direct", DomainStrategy: "prefer_ipv4"}, {Type: "block", Tag: "block"}},
		Route:     SingBoxRouteConfig{Rules: []SingBoxRouteRule{{Protocol: []string{"quic", "stun"}, Outbound: "block"}, {Network: "udp,tcp", Outbound: "direct"}}},
	}
}

func writeSingBoxJSON(sc SingBoxServerConfig){ /* ... Identical to previous versions ... */ fmt.Printf("%sWriting sb.json...%s\n",ColorYellow,ColorReset);d,e:=json.MarshalIndent(sc,"","  ");if e!=nil{log.Fatalf("Marshal failed: %v",e)}; os.WriteFile(singBoxConfig,d,0644); fmt.Printf("%sConfig written to %s%s\n",ColorGreen,singBoxConfig,ColorReset)}
func setupSystemdService(){ /* ... Identical to previous versions ... */ fmt.Printf("%sSetting systemd...%s\n",ColorYellow,ColorReset); cont:=`[Unit]
Description=Sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=/etc/s-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/s-box/sing-box run -c /etc/s-box/sb.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
`; os.WriteFile(systemdServiceFile,[]byte(cont),0644); runCommand("systemctl","daemon-reload"); runCommand("systemctl","enable","sing-box"); restartSingBoxService()}
func restartSingBoxService(){ /* ... Identical to previous versions ... */ fmt.Printf("%sRestarting Sing-box...%s\n",ColorYellow,ColorReset); if _,e:=runCommand("systemctl","restart","sing-box");e!=nil{fmt.Printf("%sWARN:Restart fail:%v%s\n",ColorYellow,e,ColorReset)}else{fmt.Printf("%sService restarted.%s\n",ColorGreen,ColorReset)}}
func getPublicIP()string{ /* ... Identical to previous versions ... */ c:=http.Client{Timeout:5*time.Second};srvs:=[]string{"https://api.ipify.org","https://api6.ipify.org","https://icanhazip.com"};for i,surl:= range srvs{res,e:=c.Get(surl);if e==nil{b,re:=io.ReadAll(res.Body);res.Body.Close();if re==nil{ip:=strings.TrimSpace(string(b));if net.ParseIP(ip)!=nil{return ip}}};if i==len(srvs)-1{fmt.Printf("%sWARN:Get IP fail:%v%s\n",ColorYellow,e,ColorReset)}};return "YOUR_SERVER_IP"}
func Btoi(isSecure bool) int { if isSecure { return 0 }; return 1 }
func generateNodeLinks()[]string{ /* ... Use the corrected generateNodeLinks from my previous reply (Version 3.2 logic) ... */ if currentInstallData.MainUUID==""{fmt.Printf("%sNo install data.%s\n",ColorYellow,ColorReset);return nil};cfg:=currentInstallData;links:=[]string{};nodeHost:=cfg.Hostname;if nodeHost==""{nodeHost="sb-server"};serverIPForLink:=cfg.ServerIP;if serverIPForLink==""||serverIPForLink=="YOUR_SERVER_IP"{serverIPForLink=getPublicIP()};isAcmeEffectivelyUsed,linkSNIForNonVLESS,addressForNonVLESSLinks:=false,defaultSNI,serverIPForLink;if cfg.UseAcmeCert&&cfg.Domain!=""{addressForNonVLESSLinks=cfg.Domain;linkSNIForNonVLESS=cfg.Domain;dAcme:=filepath.Join(acmeBaseDir,cfg.Domain);pcP,pkP:=filepath.Join(dAcme,"fullchain.pem"),filepath.Join(dAcme,"privkey.pem");if _,ce:=os.Stat(pcP);ce==nil{if _,ke:=os.Stat(pkP);ke==nil{isAcmeEffectivelyUsed=true}}};if isAcmeEffectivelyUsed{fmt.Printf("%sLinks using ACME domain: %s (certs found, insecure=0).%s\n",ColorCyan,cfg.Domain,ColorReset)}else if cfg.UseAcmeCert{fmt.Printf("%sWARN: Links use ACME domain: %s, but cert files NOT found. insecure=1 will be set.%s\n",ColorYellow,cfg.Domain,ColorReset)}else{fmt.Printf("%sLinks using IP/default SNI for non-VLESS (Self-Signed mode, insecure=1).%s\n",ColorCyan,ColorReset)};fmtAddr:=func(a string)string{ip:=net.ParseIP(a);if ip!=nil&&ip.To4()==nil&&ip.To16()!=nil{return fmt.Sprintf("[%s]",a)};return a};vlessActualConnAddr:=serverIPForLink;vlessDispAddr:=fmtAddr(vlessActualConnAddr);links=append(links,fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s-VLESS-Reality",cfg.MainUUID,vlessDispAddr,cfg.Ports["vless"],realitySNI,cfg.RealityPublicKey,cfg.RealityShortID,nodeHost));dispAddrNonVLESS:=fmtAddr(addressForNonVLESSLinks);vmObj:=map[string]interface{}{"v":"2","ps":fmt.Sprintf("%s-VMESS-WS-TLS",nodeHost),"add":addressForNonVLESSLinks,"port":strconv.Itoa(int(cfg.Ports["vmess"])),"id":cfg.MainUUID,"aid":"0","net":"ws","type":"none","host":linkSNIForNonVLESS,"path":cfg.VmessPath,"tls":"tls","sni":linkSNIForNonVLESS};vmB,_:=json.Marshal(vmObj);links=append(links,"vmess://"+base64.RawURLEncoding.EncodeToString(vmB));insecureFlagValue:=Btoi(isAcmeEffectivelyUsed&&cfg.UseAcmeCert);links=append(links,fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&insecure=%d&alpn=h3#%s-HY2",cfg.MainUUID,dispAddrNonVLESS,cfg.Ports["hysteria2"],linkSNIForNonVLESS,insecureFlagValue,nodeHost));links=append(links,fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=%d#%s-TUIC",cfg.MainUUID,cfg.MainUUID,dispAddrNonVLESS,cfg.Ports["tuic"],linkSNIForNonVLESS,insecureFlagValue,nodeHost));return links}
func displayNodeInformationFromLinks(links []string){ /* ... Identical to previous versions ... */ fmt.Printf("\n%s--- Nodes ---%s\n",ColorCyan,ColorReset);if len(links)==0{fmt.Printf("%sNo links.%s\n",ColorYellow,ColorReset);return};for _,l:=range links{var nt string;if strings.HasPrefix(l,"vless://"){nt="VLESS-Reality"};if strings.HasPrefix(l,"vmess://"){nt="VMess-WS-TLS"};if strings.HasPrefix(l,"hysteria2://"){nt="Hysteria2"};if strings.HasPrefix(l,"tuic://"){nt="TUICv5"};fmt.Printf("\n%s[%s]%s\n",ColorPurple,nt,ColorReset);fmt.Printf("  %sLink: %s%s%s\n",ColorGreen,ColorYellow,l,ColorReset);qr,e:=qrcode.New(l,qrcode.Medium);if e==nil{fmt.Printf("  %sQR:%s\n",ColorGreen,ColorReset);fmt.Println(qr.ToSmallString(true))}}}

// New function to automate Certbot setup
func runAcmeCertbotSetup() bool {
	fmt.Printf("\n%s--- ACME Certificate Automation ---%s\n", ColorCyan, ColorReset)

	// 1. Prompt for Domain
	domain := getUserInput(ColorYellow + "Enter your Fully Qualified Domain Name (e.g., sub.example.com): " + ColorReset)
	if domain == "" || !strings.Contains(domain, ".") {
		fmt.Printf("%sInvalid domain name. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}
	currentInstallData.Domain = domain // Store it even if setup fails, for user convenience

	// 2. Prompt for Email
	email := getUserInput(ColorYellow + "Enter your email address for Certbot (e.g., your@example.com): " + ColorReset)
	if email == "" || !strings.Contains(email, "@") {
		fmt.Printf("%sInvalid email address. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}
	currentInstallData.AcmeEmail = email // Store it

	currentIP := getPublicIP()
	fmt.Printf("%sIMPORTANT: Before proceeding, ensure the following:%s\n", ColorYellow, ColorReset)
	fmt.Printf("  %s1. DNS A (and/or AAAA) record for '%s%s%s' MUST point to this server's public IP: %s%s%s%s\n", ColorCyan, ColorYellow, domain, ColorCyan, ColorYellow, currentIP, ColorCyan, ColorReset)
	fmt.Printf("  %s2. Port 80 on this server must be OPEN (firewall & not in use by another service) for Certbot's HTTP-01 challenge.%s\n", ColorCyan, ColorReset)

	dnsCheckConfirm := getUserInput(ColorYellow + "Have you verified the DNS record and ensured port 80 is open in your firewall? (y/N): " + ColorReset)
	if strings.ToLower(dnsCheckConfirm) != "y" {
		fmt.Printf("%sDNS/Firewall verification not confirmed. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}

	// Check if port 80 is free
	fmt.Printf("%sChecking if port 80 is currently in use (for Certbot's '--standalone' mode)...%s\n", ColorYellow, ColorReset)
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("%sError: Port 80 is likely in use by another application: %v%s\n", ColorRed, err, ColorReset)
		fmt.Printf("%sPlease stop the conflicting service (e.g., Nginx, Apache) and retry. You can check with: sudo ss -tulnp | grep ':80'%s\n", ColorRed, ColorReset)
		fmt.Printf("%sACME setup aborted due to port 80 issue.%s\n", ColorRed, ColorReset)
		return false
	}
	listener.Close() // Release port 80
	fmt.Printf("%sPort 80 appears to be free for Certbot's '--standalone' mode.%s\n", ColorGreen, ColorReset)

	// Check if certbot is installed
	if _, err := exec.LookPath("certbot"); err != nil {
		fmt.Printf("%sERROR: Certbot is not found in your system's PATH. Please install it manually or check installation:%s\n", ColorRed, ColorReset)
		fmt.Printf("%s  sudo apt install certbot -y OR sudo snap install --classic certbot && sudo ln -s /snap/bin/certbot /usr/bin/certbot%s\n", ColorCyan, ColorReset)
		fmt.Printf("%sACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}

	fmt.Printf("\n%sAttempting to obtain certificate for %s%s%s using Certbot...%s\n", ColorYellow, ColorCyan, domain, ColorYellow, ColorReset)
	certbotArgs := []string{"certonly", "--standalone", "--noninteractive", "--email", email, "--agree-tos", "-d", domain}
	certbotOutput, certbotErr := runCommand("certbot", certbotArgs...)

	if certbotErr != nil {
		fmt.Printf("%sCertbot failed to obtain certificate:%s\n", ColorRed, ColorReset)
		fmt.Printf("%sError: %v%s\n", ColorRed, certbotErr, ColorReset)
		fmt.Printf("%sOutput: %s%s\n", ColorRed, certbotOutput, ColorReset)
		fmt.Printf("%sPlease check your DNS settings, firewall, and ensure port 80 is truly free. ACME setup aborted.%s\n", ColorRed, ColorReset)
		return false
	}

	fmt.Printf("%sCertbot successfully obtained certificate.%s\n", ColorGreen, ColorReset)

	// Copy/Symlink certificates
	domainAcmeDir := filepath.Join(acmeBaseDir, domain)
	destCertPath := filepath.Join(domainAcmeDir, "fullchain.pem")
	destKeyPath := filepath.Join(domainAcmeDir, "privkey.pem")

	// Ensure destination directory exists
	if err := os.MkdirAll(domainAcmeDir, 0755); err != nil {
		fmt.Printf("%sERROR: Could not create ACME destination directory %s: %v%s\n", ColorRed, domainAcmeDir, err, ColorReset)
		return false
	}

	// Paths where Certbot places them
	sourceCertPath := filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	sourceKeyPath := filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")

	fmt.Printf("%sCopying certificate files to Sing-box directory...%s\n", ColorYellow, ColorReset)

	// Copy fullchain.pem
	if _, err := runCommand("cp", sourceCertPath, destCertPath); err != nil {
		fmt.Printf("%sERROR: Failed to copy fullchain.pem: %v%s\n", ColorRed, err, ColorReset)
		return false
	}
	// Copy privkey.pem
	if _, err := runCommand("cp", sourceKeyPath, destKeyPath); err != nil {
		fmt.Printf("%sERROR: Failed to copy privkey.pem: %v%s\n", ColorRed, err, ColorReset)
		return false
	}

	// Set permissions
	if _, err := runCommand("chmod", "644", destCertPath); err != nil {
		fmt.Printf("%sWARN: Failed to set permissions on %s: %v%s\n", ColorYellow, destCertPath, err, ColorReset)
	}
	if _, err := runCommand("chmod", "600", destKeyPath); err != nil {
		fmt.Printf("%sWARN: Failed to set permissions on %s: %v%s\n", ColorYellow, destKeyPath, err, ColorReset)
	}
	if _, err := runCommand("chown", "root:root", destCertPath, destKeyPath); err != nil {
		fmt.Printf("%sWARN: Failed to set ownership on certificate files: %v%s\n", ColorYellow, err, ColorReset)
	}

	// Final check for files
	_, certErr := os.Stat(destCertPath)
	_, keyErr := os.Stat(destKeyPath)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		fmt.Printf("%sERROR: Certificates were not found at the destination after copying:%s\n", ColorRed, ColorReset)
		if os.IsNotExist(certErr) {
			fmt.Printf("  Missing: %s%s%s\n", ColorRed, destCertPath, ColorReset)
		}
		if os.IsNotExist(keyErr) {
			fmt.Printf("  Missing: %s%s%s\n", ColorRed, destKeyPath, ColorReset)
		}
		fmt.Printf("%sACME certificate setup failed after Certbot run. Sing-box will use self-signed certificates.%s\n", ColorRed, ColorReset)
		return false
	}

	fmt.Printf("%sACME certificate automation complete for '%s'. Files are in %s%s%s. Sing-box will be configured to use them.%s\n", ColorGreen, ColorCyan, domain, ColorGreen, domainAcmeDir, ColorReset)
	return true
}


func installInteractive(){ /* ... Use the corrected installInteractive from my previous reply (Version 3.2 logic with early self-signed gen and better ACME warnings) ... */ fmt.Printf("%sInstall/Reinstall...%s\n",ColorYellow,ColorReset);checkRoot();checkOS();installDependencies();os.MkdirAll(singBoxDir,0755);os.MkdirAll(acmeBaseDir,0755);downloadAndInstallSingBox();fmt.Printf("%sGenerating base self-signed certificates as a fallback...%s\n",ColorYellow,ColorReset);generateSelfSignedCert();loadInstallData();fmt.Printf("\n%s--- Ports ---%s\n",ColorCyan,ColorReset);if currentInstallData.Ports==nil{currentInstallData.Ports=make(map[string]uint16)};currentInstallData.Ports["vless"]=getPort("VLESS",currentInstallData.Ports["vless"]);currentInstallData.Ports["vmess"]=getPort("VMess",currentInstallData.Ports["vmess"]);currentInstallData.Ports["hysteria2"]=getPort("Hy2",currentInstallData.Ports["hysteria2"]);currentInstallData.Ports["tuic"]=getPort("TUIC",currentInstallData.Ports["tuic"]);currentInstallData.MainUUID=generateSingBoxUUID();fmt.Printf("%sUUID:%s%s%s\n",ColorGreen,ColorYellow,currentInstallData.MainUUID,ColorReset);currentInstallData.VmessPath=fmt.Sprintf("/%s-vm",currentInstallData.MainUUID);privK,pubK,sID,e:=generateRealityKeyPair();if e!=nil{log.Fatalf("Gen Reality fail:%v",e)};currentInstallData.RealityPrivateKey,currentInstallData.RealityPublicKey,currentInstallData.RealityShortID=privK,pubK,sID;fmt.Printf("%sPubKey:%s%s%s\n",ColorGreen,ColorYellow,pubK,ColorReset);fmt.Printf("%sShortID:%s%s%s\n",ColorGreen,ColorYellow,sID,ColorReset);fmt.Printf("\n%s--- Certs ---%s\n",ColorCyan,ColorReset);certChoice:=getUserInput(ColorYellow+"Use ACME (domain) certificate for VMess/Hysteria2/TUIC? (y/N): "+ColorReset);if strings.ToLower(certChoice)=="y"{
		if runAcmeCertbotSetup() { // Call the new automation function
			currentInstallData.UseAcmeCert = true
			// Domain and Email are already stored by runAcmeCertbotSetup()
		} else {
			fmt.Printf("%sACME setup failed. Using self-signed certificates.%s\n", ColorYellow, ColorReset)
			currentInstallData.UseAcmeCert = false
			currentInstallData.Domain = ""    // Clear domain if ACME failed
			currentInstallData.AcmeEmail = "" // Clear email if ACME failed
		}
	}else{fmt.Printf("%sUsing self-signed certificates.%s\n",ColorGreen,ColorReset);currentInstallData.UseAcmeCert=false;currentInstallData.Domain="";currentInstallData.AcmeEmail=""};currentInstallData.ServerIP=getPublicIP();currentInstallData.Hostname,_=os.Hostname();if currentInstallData.Hostname==""{currentInstallData.Hostname="sb-server"};saveInstallData();serverCfg:=buildSingBoxServerConfig();writeSingBoxJSON(serverCfg);setupSystemdService();time.Sleep(1*time.Second);statusText,isRunning:=getSingBoxStatus();if !isRunning&&currentInstallData.UseAcmeCert&&currentInstallData.Domain!=""{domainAcmeDir:=filepath.Join(acmeBaseDir,currentInstallData.Domain);certPath:=filepath.Join(domainAcmeDir,"fullchain.pem");keyPath:=filepath.Join(domainAcmeDir,"privkey.pem");_,cE:=os.Stat(certPath);_,kE:=os.Stat(keyPath);if os.IsNotExist(cE)||os.IsNotExist(kE){fmt.Printf("\n%sIMPORTANT WARNING:%s\n%sSing-box service is %s%s%s. Likely because ACME certs for '%s%s%s' are missing at:\n  Cert: %s\n  Key:  %s\nPlease place certs or switch to self-signed via menu.%s\n",ColorRed,ColorReset,ColorRed,statusText,ColorReset,ColorYellow,ColorCyan,currentInstallData.Domain,ColorYellow,certPath,keyPath,ColorReset)}}else if!isRunning{fmt.Printf("\n%sWARN: Sing-box is %s%s%s. Check logs (option 9).%s\n",ColorRed,statusText,ColorReset,ColorYellow,ColorReset)};displayNodeInformationFromLinks(generateNodeLinks());cleanupInstallationFiles();execP,e:=os.Executable();if e==nil{slP:=filepath.Join("/usr/local/bin",cliCommandName);if _,le:=os.Lstat(slP);le==nil{os.Remove(slP)};if errSym := os.Symlink(execP,slP);errSym!=nil{fmt.Printf("\n%sWARN:Symlink %s fail: %v%s\n",ColorYellow,cliCommandName,errSym,ColorReset)}else{fmt.Printf("\n%sUse 'sudo %s' to manage.%s\n",ColorGreen,cliCommandName,ColorReset)}};fmt.Printf("\n%sInstall OK.%s\n",ColorGreen,ColorReset)}
func uninstall(){/* ... Identical to Version 3.1/3.6 ... */ checkRoot();fmt.Printf("%sUninstalling...%s\n",ColorYellow,ColorReset);slP:=filepath.Join("/usr/local/bin",cliCommandName);if err:=os.Remove(slP);err==nil{fmt.Printf("%sRemoved command symlink: %s%s\n",ColorGreen,slP,ColorReset)} else if !os.IsNotExist(err){fmt.Printf("%sWARN:Could not remove symlink %s: %v%s\n",ColorYellow,slP,err,ColorReset)};runCommand("systemctl","stop","sing-box");runCommand("systemctl","disable","sing-box");os.Remove(systemdServiceFile);if err:=os.RemoveAll(singBoxDir);err!=nil{fmt.Printf("%sWARN:Failed to remove dir %s: %v%s\n",ColorYellow,singBoxDir,err,ColorReset)};runCommand("systemctl","daemon-reload");fmt.Printf("%sSing-box uninstalled.%s\n",ColorGreen,ColorReset)}
func manageNodes(){/* ... Identical to Version 3.1/3.6 ... */ if _,e:=os.Stat(installConfigFile);e!=nil{fmt.Printf("%sNot installed or data missing. Please install first.%s\n",ColorYellow,ColorReset);return};displayNodeInformationFromLinks(generateNodeLinks())}
func manageCertificates(){ /* ... Use the UNCOMPRESSED manageCertificates from Version 3.2 that handles ACME reconfig and file checks ... */
	checkRoot();if _,e:=os.Stat(installConfigFile);e!=nil{fmt.Printf("%sNot installed or data missing.%s\n",ColorYellow,ColorReset);return}
	// Make sure currentInstallData is loaded before displaying current setting
	loadInstallData()

	fmt.Printf("\n%s--- Manage Certificates ---%s\n",ColorCyan,ColorReset);fmt.Printf("Current setting: Use ACME Certificate = %s%v%s",ColorYellow,currentInstallData.UseAcmeCert,ColorReset);if currentInstallData.UseAcmeCert{fmt.Printf(" (Domain: %s%s%s, Email: %s%s%s)\n",ColorYellow,currentInstallData.Domain,ColorReset,ColorYellow,currentInstallData.AcmeEmail,ColorReset)}else{fmt.Printf(" %s(Using Self-Signed)%s\n",ColorYellow,ColorReset)}
	fmt.Printf("%s1. Switch to/Reconfigure ACME (Domain) Certificate%s\n",ColorGreen,ColorReset);fmt.Printf("%s2. Switch to Self-Signed Certificate%s\n",ColorGreen,ColorReset);fmt.Printf("%s0. Back to Main Menu%s\n",ColorYellow,ColorReset)
	choice:=getUserInput(ColorYellow+"Choice: "+ColorReset);switchedConfig:=false
	switch choice{
	case "1":
		originalDomain,originalUseAcme,originalEmail:=currentInstallData.Domain,currentInstallData.UseAcmeCert,currentInstallData.AcmeEmail
		if currentInstallData.UseAcmeCert{
			fmt.Printf("%sCurrently using ACME for domain: %s%s%s\n",ColorYellow,ColorBlue,currentInstallData.Domain,ColorReset)
			if strings.ToLower(getUserInput(ColorYellow+"Reconfigure for this domain or a new one? (y/N): "+ColorReset))!="y"{
				fmt.Printf("%sNo changes made to ACME configuration.%s\n",ColorYellow,ColorReset);return
			}
		}

		if runAcmeCertbotSetup() { // Call the new automation function
			currentInstallData.UseAcmeCert = true
			switchedConfig = true
			fmt.Printf("%sSing-box is now configured to use ACME for domain: %s%s%s\n", ColorGreen, ColorBlue, currentInstallData.Domain, ColorReset)
		} else {
			fmt.Printf("%sACME setup failed. Reverting to previous certificate settings.%s\n", ColorRed, ColorReset)
			if originalUseAcme {
				currentInstallData.Domain = originalDomain
				currentInstallData.AcmeEmail = originalEmail
				currentInstallData.UseAcmeCert = true
				fmt.Printf("%sReverted to previous ACME settings for domain: %s%s%s\n", ColorYellow, originalDomain, ColorReset)
			} else {
				currentInstallData.UseAcmeCert = false
				currentInstallData.Domain = ""
				currentInstallData.AcmeEmail = ""
				fmt.Printf("%sReverted to Self-Signed settings.%s\n", ColorYellow, ColorReset)
			}
			// No config change if ACME setup failed, so switchedConfig remains false
		}
	case "2":
		if !currentInstallData.UseAcmeCert && currentInstallData.Domain == "" {
			fmt.Printf("%sAlready using self-signed certificate. No change made.%s\n",ColorYellow,ColorReset);return
		}
		fmt.Printf("%sSwitching to self-signed certificate...%s\n",ColorYellow,ColorReset);generateSelfSignedCert()
		currentInstallData.UseAcmeCert=false;currentInstallData.Domain="";currentInstallData.AcmeEmail="";switchedConfig=true
		fmt.Printf("%sSuccessfully switched to self-signed certificate.%s\n",ColorGreen,ColorReset)
	case "0": return
	default: fmt.Printf("%sInvalid choice. Please try again.%s\n",ColorRed,ColorReset);return
	}
	if switchedConfig{saveInstallData();fmt.Printf("%sRebuilding Sing-box server configuration...%s\n",ColorYellow,ColorReset);serverCfg:=buildSingBoxServerConfig();writeSingBoxJSON(serverCfg);restartSingBoxService();fmt.Printf("%sSing-box configuration has been updated and service restarted.%s\n",ColorGreen,ColorReset);manageNodes()}
}

func generateAndShowSubscription(){/* ... Identical to previous versions ... */ if _,e:=os.Stat(installConfigFile);e!=nil{fmt.Printf("%sNot installed or data missing.%s\n",ColorYellow,ColorReset);return};links:=generateNodeLinks();if len(links)==0{fmt.Printf("%sNo nodes configured.%s\n",ColorYellow,ColorReset);return};var sbS strings.Builder;for _,l:=range links{sbS.WriteString(l+"\n")};b64s:=base64.StdEncoding.EncodeToString([]byte(sbS.String()));fmt.Printf("\n%s--- Subscription (Base64) ---%s\n",ColorCyan,ColorReset);fmt.Println(ColorYellow+b64s+ColorReset);fmt.Printf("\n%sCopy and import.%s\n",ColorGreen,ColorReset)}
func cleanupInstallationFiles(){/* ... Identical to previous versions ... */ td:=os.TempDir();pats:=[]string{"sing-box-*.tar.gz","sb-extract"};for _,p:=range pats{items,_:=filepath.Glob(filepath.Join(td,p));for _,i:=range items{info,_:=os.Stat(i);if info!=nil{if info.IsDir(){os.RemoveAll(i)}else{os.Remove(i)}}}};fmt.Printf("%sTemporary installation files cleaned.%s\n",ColorGreen,ColorReset)}
func restartSingBoxServiceInteractive(){checkRoot();restartSingBoxService()}
func stopSingBoxServiceInteractive(){checkRoot();fmt.Printf("%sStopping service...%s\n",ColorYellow,ColorReset);if _,e:=runCommand("systemctl","stop","sing-box");e!=nil{fmt.Printf("%sWARN:Stop fail:%v%s\n",ColorYellow,e,ColorReset)}else{fmt.Printf("%sService stopped.%s\n",ColorGreen,ColorReset)}}
func startSingBoxServiceInteractive(){checkRoot();fmt.Printf("%sStarting service...%s\n",ColorYellow,ColorReset);runCommand("systemctl","enable","sing-box");if _,e:=runCommand("systemctl","start","sing-box");e!=nil{fmt.Printf("%sWARN:Start fail:%v%s\n",ColorYellow,e,ColorReset)}else{fmt.Printf("%sService started.%s\n",ColorGreen,ColorReset)}}
func viewSingBoxLogs(){/* ... Identical to previous versions ... */ fmt.Printf("%sDisplaying Sing-box logs (Ctrl+C to exit):%s\n",ColorYellow,ColorReset);cmd:=exec.Command("journalctl","-u","sing-box","-f","-e","--no-pager");cmd.Stdout=os.Stdout;cmd.Stderr=os.Stderr;err:=cmd.Run();if err!=nil{if exitError,ok:=err.(*exec.ExitError);ok{fmt.Printf("\n%sLog viewing ended: %v%s\n",ColorYellow,exitError,ColorReset);return};fmt.Printf("%sLog view error: %v%s\n",ColorRed,err,ColorReset)}}